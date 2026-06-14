import { memo, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { APInfo, ClientInfo } from "../api";

// ---------------------------------------------------------------------------
// Stable, non-overlapping layout
// ---------------------------------------------------------------------------
//
// Geometry:
//   * APs are arranged on a circle around the origin. The ring radius scales
//     linearly with AP count so the arc between neighbours stays >= the
//     widest AP card, guaranteeing no overlap on the ring itself.
//   * Each AP owns a single radial ray pointing outward from the origin
//     through that AP. Its associated clients are stacked along that ray at
//     increasing distances. Because adjacent rays diverge as r grows, two
//     APs' radial chains never collide.
//   * Orphan clients (no AP, or AP not currently visible) live on dedicated
//     outer rings beyond the AP-client area, distributed uniformly per ring
//     so they don't pile up.
//
// Stability:
//   * Each AP keeps a cached angular slot. New APs are inserted at the
//     midpoint of the largest free gap, so existing APs never shift.
//   * Each client is anchored to a deterministic slot index per AP (or per
//     orphan pool). Slot indices are assigned monotonically and never reused,
//     so a client's relative position is preserved for the lifetime of the
//     session. Absolute position only changes when the AP ring radius itself
//     scales (i.e., the total AP count changes).

interface Pos {
  x: number;
  y: number;
}

interface ClientSlot {
  /** BSSID of the AP the client is anchored to, or undefined for orphans. */
  ap?: string;
  /** Slot index within that AP's radial chain, or within the orphan pool. */
  slotIdx: number;
}

interface LayoutCache {
  apAngles: Map<string, number>; // bssid -> angle (radians)
  clientSlot: Map<string, ClientSlot>; // mac -> slot anchor
}

function newLayoutCache(): LayoutCache {
  return { apAngles: new Map(), clientSlot: new Map() };
}

const TWO_PI = Math.PI * 2;

// Visual budgets (px). Tuned for the AP/client card sizes used below.
const AP_NODE_WIDTH = 240;
const CLIENT_NODE_WIDTH = 160;
const CLIENT_RADIAL_PITCH = 110;
const FIRST_CLIENT_OFFSET = 140;

// AP ring radius — large enough that the chord between neighbouring APs
// exceeds the widest AP card. The clamp keeps small graphs from becoming
// claustrophobic.
function computeAPRadius(count: number): number {
  if (count <= 1) return 280;
  // Required arc length between APs >= AP_NODE_WIDTH + margin.
  const arc = AP_NODE_WIDTH + 60;
  return Math.max(320, (arc * count) / TWO_PI);
}

// Pick the angular position for a new AP: midpoint of the widest gap among
// already-placed angles. With a single existing angle we place opposite it.
function pickGapAngle(existing: number[]): number {
  if (existing.length === 0) return 0;
  if (existing.length === 1) return (existing[0] + Math.PI) % TWO_PI;
  const sorted = [...existing].sort((a, b) => a - b);
  let bestGap = -Infinity;
  let bestMid = 0;
  for (let i = 0; i < sorted.length; i++) {
    const a = sorted[i];
    const b = i === sorted.length - 1 ? sorted[0] + TWO_PI : sorted[i + 1];
    const gap = b - a;
    if (gap > bestGap) {
      bestGap = gap;
      bestMid = (a + gap / 2) % TWO_PI;
    }
  }
  return bestMid;
}

// Map an orphan slot index to a position on a sequence of concentric rings
// outside the AP/client area. Capacity per ring scales with circumference so
// nodes never overlap regardless of the orphan count.
function orphanPosition(slotIdx: number, baseRadius: number): Pos {
  const pitch = 130;
  const ringSpacing = 140;
  let consumed = 0;
  for (let ring = 0; ring < 64; ring++) {
    const r = baseRadius + ring * ringSpacing;
    const cap = Math.max(8, Math.floor((TWO_PI * r) / pitch));
    if (slotIdx < consumed + cap) {
      const inRing = slotIdx - consumed;
      const ang = (inRing / cap) * TWO_PI;
      return { x: r * Math.cos(ang), y: r * Math.sin(ang) };
    }
    consumed += cap;
  }
  return { x: baseRadius, y: 0 };
}

interface NodeDataAP extends Record<string, unknown> {
  kind: "ap";
  info: APInfo;
}

interface NodeDataClient extends Record<string, unknown> {
  kind: "client";
  info: ClientInfo;
}

type GraphNode = Node<NodeDataAP | NodeDataClient>;

interface BuildResult {
  nodes: GraphNode[];
  edges: Edge[];
}

function buildLayout(
  aps: APInfo[],
  clients: ClientInfo[],
  cache: LayoutCache,
): BuildResult {
  // 1. Drop entries for vanished nodes.
  const liveAPs = new Set(aps.map((a) => a.bssid));
  const liveCs = new Set(clients.map((c) => c.mac));
  for (const k of [...cache.apAngles.keys()]) {
    if (!liveAPs.has(k)) cache.apAngles.delete(k);
  }
  for (const k of [...cache.clientSlot.keys()]) {
    if (!liveCs.has(k)) cache.clientSlot.delete(k);
  }

  // 2. Assign angles to brand-new APs.
  const newAPs = aps.filter((a) => !cache.apAngles.has(a.bssid));
  if (cache.apAngles.size === 0 && newAPs.length > 0) {
    newAPs.forEach((a, i) => {
      cache.apAngles.set(a.bssid, (i * TWO_PI) / newAPs.length);
    });
  } else {
    for (const a of newAPs) {
      cache.apAngles.set(a.bssid, pickGapAngle([...cache.apAngles.values()]));
    }
  }

  // 3. AP positions.
  const apRadius = computeAPRadius(aps.length);
  const apPos = new Map<string, Pos>();
  for (const a of aps) {
    const ang = cache.apAngles.get(a.bssid) ?? 0;
    apPos.set(a.bssid, {
      x: apRadius * Math.cos(ang),
      y: apRadius * Math.sin(ang),
    });
  }

  // 4. (Re)assign client slots. A client's anchor changes only when its
  //    current bssid no longer matches the cached one (e.g., a client roams
  //    between APs, or its AP disappears from the visible set).
  const apMaxSlot = new Map<string, number>(); // ap -> highest used slot
  let orphanMax = -1;
  // Seed from cache so we don't collide with existing slots.
  for (const slot of cache.clientSlot.values()) {
    if (slot.ap && liveAPs.has(slot.ap)) {
      apMaxSlot.set(slot.ap, Math.max(apMaxSlot.get(slot.ap) ?? -1, slot.slotIdx));
    } else if (!slot.ap) {
      orphanMax = Math.max(orphanMax, slot.slotIdx);
    }
  }

  // Demote stale anchors and promote/assign new clients.
  for (const c of clients) {
    const desired = c.bssid && liveAPs.has(c.bssid) ? c.bssid : undefined;
    const cached = cache.clientSlot.get(c.mac);
    if (cached && cached.ap === desired) continue;

    // Anchor migration or first-time assignment: drop the old slot index
    // (we never reclaim it for stability of remaining clients) and pick the
    // next free slot in the destination pool.
    if (desired) {
      const next = (apMaxSlot.get(desired) ?? -1) + 1;
      apMaxSlot.set(desired, next);
      cache.clientSlot.set(c.mac, { ap: desired, slotIdx: next });
    } else {
      orphanMax += 1;
      cache.clientSlot.set(c.mac, { slotIdx: orphanMax });
    }
  }

  // 5. Compute absolute client positions.
  const clientPos = new Map<string, Pos>();
  // Approximate worst-case AP-chain extent so orphans land beyond it.
  let maxApSlot = 0;
  for (const v of apMaxSlot.values()) {
    if (v > maxApSlot) maxApSlot = v;
  }
  const apChainOuterR =
    apRadius + FIRST_CLIENT_OFFSET + (maxApSlot + 1) * CLIENT_RADIAL_PITCH;
  const orphanBase = apChainOuterR + 220;

  for (const c of clients) {
    const slot = cache.clientSlot.get(c.mac);
    if (!slot) continue;
    if (slot.ap && apPos.has(slot.ap)) {
      const ang = cache.apAngles.get(slot.ap) ?? 0;
      const r =
        apRadius + FIRST_CLIENT_OFFSET + slot.slotIdx * CLIENT_RADIAL_PITCH;
      clientPos.set(c.mac, { x: r * Math.cos(ang), y: r * Math.sin(ang) });
    } else {
      clientPos.set(c.mac, orphanPosition(slot.slotIdx, orphanBase));
    }
  }

  // 6. Materialize React Flow nodes and edges.
  const nodes: GraphNode[] = [];
  for (const a of aps) {
    const p = apPos.get(a.bssid)!;
    nodes.push({
      id: `ap:${a.bssid}`,
      type: "ap",
      position: p,
      data: { kind: "ap", info: a },
      draggable: false,
      selectable: true,
      connectable: false,
    });
  }
  for (const c of clients) {
    const p = clientPos.get(c.mac);
    if (!p) continue;
    nodes.push({
      id: `client:${c.mac}`,
      type: "client",
      position: p,
      data: { kind: "client", info: c },
      draggable: false,
      selectable: false,
      connectable: false,
    });
  }

  const edges: Edge[] = [];
  for (const c of clients) {
    const slot = cache.clientSlot.get(c.mac);
    if (!slot?.ap || !liveAPs.has(slot.ap)) continue;
    edges.push({
      id: `e:${slot.ap}->${c.mac}`,
      source: `ap:${slot.ap}`,
      target: `client:${c.mac}`,
      animated: c.associated,
      style: {
        stroke: c.associated ? "#A9DC76" : "#5b595c",
        strokeWidth: c.associated ? 1.4 : 1,
      },
    });
  }

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Custom node renderers
// ---------------------------------------------------------------------------
//
// A single zero-size handle is centered on each node so that edges terminate
// at the node's visual centre regardless of the node's content width.

const HIDDEN_HANDLE_STYLE: React.CSSProperties = {
  left: "50%",
  top: "50%",
  transform: "translate(-50%, -50%)",
  opacity: 0,
  pointerEvents: "none",
  width: 1,
  height: 1,
  border: "none",
  background: "transparent",
};

const APNode = memo(function APNode({ data }: NodeProps<Node<NodeDataAP>>) {
  const a = data.info;
  return (
    <div
      className="px-3 py-1.5 rounded border-2 border-mono-yellow bg-bg2 text-fg shadow-md"
      style={{ minWidth: 140, maxWidth: AP_NODE_WIDTH }}
    >
      <Handle type="source" position={Position.Top} style={HIDDEN_HANDLE_STYLE} />
      <div className="text-[10px] uppercase tracking-wider text-mono-yellow font-semibold flex justify-between gap-2">
        <span>AP</span>
        <span>ch {a.channel}</span>
      </div>
      <div className="text-sm font-medium truncate">
        {a.hidden ? <span className="text-slate-500">&lt;hidden&gt;</span> : a.ssid || a.bssid}
      </div>
      <div className="text-[10px] text-muted mono truncate">{a.bssid}</div>
      <div className="text-[10px] text-muted">{a.rssi} dBm</div>
    </div>
  );
});

const ClientNode = memo(function ClientNode({ data }: NodeProps<Node<NodeDataClient>>) {
  const c = data.info;
  const border = c.associated ? "border-mono-green" : "border-border";
  return (
    <div
      className={`px-2 py-1 rounded border bg-bg2 text-fg shadow-sm ${border}`}
      style={{ maxWidth: CLIENT_NODE_WIDTH }}
    >
      <Handle type="target" position={Position.Top} style={HIDDEN_HANDLE_STYLE} />
      <div className="mono text-[11px] truncate">{c.mac}</div>
      <div className="text-[9px] text-muted flex gap-2">
        <span>ch {c.channel}</span>
        <span>{c.rssi} dBm</span>
        {c.associated && <span className="text-mono-green">assoc</span>}
      </div>
    </div>
  );
});

const NODE_TYPES: NodeTypes = {
  ap: APNode as unknown as NodeTypes[string],
  client: ClientNode as unknown as NodeTypes[string],
};

// ---------------------------------------------------------------------------
// Zoom / fit controls overlay
// ---------------------------------------------------------------------------

function ZoomControls() {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  return (
    <div className="absolute top-3 right-3 z-10 flex gap-1 bg-bg2/90 border border-border rounded shadow backdrop-blur-sm">
      <button
        type="button"
        className="px-2 py-1 text-fg hover:bg-bg3 rounded-l"
        onClick={() => zoomOut({ duration: 200 })}
        title="Zoom out"
        aria-label="Zoom out"
      >
        −
      </button>
      <button
        type="button"
        className="px-2 py-1 text-fg hover:bg-bg3 border-x border-border"
        onClick={() => fitView({ duration: 300, padding: 0.15 })}
        title="Fit to window"
        aria-label="Fit to window"
      >
        ⤢
      </button>
      <button
        type="button"
        className="px-2 py-1 text-fg hover:bg-bg3 rounded-r"
        onClick={() => zoomIn({ duration: 200 })}
        title="Zoom in"
        aria-label="Zoom in"
      >
        +
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------

interface GraphCanvasProps {
  aps: APInfo[];
  clients: ClientInfo[];
  onAPClick?: (bssid: string) => void;
}

function GraphCanvas({ aps, clients, onAPClick }: GraphCanvasProps) {
  const cacheRef = useRef<LayoutCache>(newLayoutCache());
  // Lazy initializer keeps the first render in sync with the data.
  const [graph, setGraph] = useState<BuildResult>(() =>
    buildLayout(aps, clients, cacheRef.current),
  );

  useEffect(() => {
    setGraph(buildLayout(aps, clients, cacheRef.current));
  }, [aps, clients]);

  const empty = graph.nodes.length === 0;

  return (
    <div className="relative w-full h-full">
      <ReactFlow
        nodes={graph.nodes}
        edges={graph.edges}
        nodeTypes={NODE_TYPES}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        panOnDrag
        zoomOnScroll
        zoomOnPinch
        zoomOnDoubleClick={false}
        panOnScroll={false}
        // Lower minZoom because the graph spans thousands of px when many APs
        // are present; fitView needs room to scale all the way down.
        minZoom={0.02}
        maxZoom={3}
        fitView
        proOptions={{ hideAttribution: false }}
        onNodeClick={(_, node) => {
          if (onAPClick && node.type === "ap") {
            const data = node.data as NodeDataAP;
            onAPClick(data.info.bssid);
          }
        }}
        style={{ background: "#221f22" }}
      >
        <Background color="#403e41" gap={28} size={1} />
        <ZoomControls />
      </ReactFlow>
      {empty && (
        <div className="absolute inset-0 flex items-center justify-center text-muted pointer-events-none">
          No data.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Public component
// ---------------------------------------------------------------------------

export interface EnvironmentGraphProps {
  aps: APInfo[];
  clients: ClientInfo[];
  /** Optional drill-down: invoked when an AP node is clicked. */
  onAPClick?: (bssid: string) => void;
}

export default function EnvironmentGraph(props: EnvironmentGraphProps) {
  // Dedicated card with an explicit height — React Flow needs a sized parent.
  const heightStyle = useMemo<React.CSSProperties>(() => ({ height: "70vh", minHeight: 480 }), []);
  return (
    <div className="card mt-4 p-0 overflow-hidden" style={heightStyle}>
      <ReactFlowProvider>
        <GraphCanvas {...props} />
      </ReactFlowProvider>
    </div>
  );
}

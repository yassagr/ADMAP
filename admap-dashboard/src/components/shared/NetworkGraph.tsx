/**
 * Graphe réseau interactif générique (force-directed, SVG pur).
 *
 * Layout délégué à `useForceSimulation` (TS pur, sans dépendance). Interactions :
 * zoom molette (centré curseur), pan (drag du fond), drag de nœud (épinglé le
 * temps du geste), clic sur nœud. Agnostique du domaine : un appelant fournit
 * `nodes`/`links` génériques + des accesseurs. Réutilisable par M2 (réseau d'IPs)
 * et M4 (graphe de clusters).
 */
import {
  useEffect,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";

import { cn } from "@/lib/utils";
import { useForceSimulation } from "@/hooks/useForceSimulation";
import type { SimLink, SimNodeInput } from "@/lib/forceSimulation";

/** Nœud public du graphe. */
export interface GraphNode {
  id: string;
  label?: string;
  /** Couleur de remplissage (défaut : cyan d'accent). */
  color?: string;
  /** Rayon en px (défaut 9). */
  size?: number;
}

/** Arête publique du graphe. */
export interface GraphLink {
  source: string;
  target: string;
  color?: string;
}

export interface NetworkGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  /** Hauteur du cadre (px). Largeur = responsive via viewBox. */
  height?: number;
  /** Nœud mis en évidence (anneau blanc). */
  selectedId?: string | null;
  onNodeClick?: (node: GraphNode) => void;
  emptyMessage?: string;
  className?: string;
}

/** Largeur virtuelle de l'espace de simulation (le viewBox la met à l'échelle). */
const VIEW_W = 800;
const MIN_ZOOM = 0.3;
const MAX_ZOOM = 4;
/** Déplacement viewBox max pour considérer un pointer-up comme un clic. */
const CLICK_SLOP = 4;

interface Transform {
  k: number;
  tx: number;
  ty: number;
}

type Interaction =
  | { mode: "none" }
  | { mode: "pan"; lastX: number; lastY: number }
  | { mode: "node"; id: string; lastX: number; lastY: number; downX: number; downY: number; moved: boolean };

function clampZoom(k: number): number {
  return Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, k));
}

export function NetworkGraph({
  nodes,
  links,
  height = 460,
  selectedId = null,
  onNodeClick,
  emptyMessage = "Aucune donnée à visualiser.",
  className,
}: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [transform, setTransform] = useState<Transform>({ k: 1, tx: 0, ty: 0 });
  const transformRef = useRef(transform);
  const interactionRef = useRef<Interaction>({ mode: "none" });

  // Miroir du transform dans une ref (lue par le listener wheel natif et les
  // handlers pointeur), synchronisée hors render (règle `react-hooks/refs`).
  useEffect(() => {
    transformRef.current = transform;
  }, [transform]);

  const inputs: SimNodeInput[] = nodes.map((n) => ({
    id: n.id,
    radius: n.size ?? 9,
  }));
  const simLinks: SimLink[] = links.map((l) => ({
    source: l.source,
    target: l.target,
  }));

  const { nodes: simNodes, startDrag, dragTo, endDrag } = useForceSimulation(
    inputs,
    simLinks,
    VIEW_W,
    height,
  );

  const posById = new Map(simNodes.map((n) => [n.id, n]));

  /** Coordonnées client → coordonnées viewBox. */
  const toViewBox = (clientX: number, clientY: number): { x: number; y: number } => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return {
      x: ((clientX - rect.left) / rect.width) * VIEW_W,
      y: ((clientY - rect.top) / rect.height) * height,
    };
  };

  /** Coordonnées viewBox → coordonnées du graphe (inverse du transform). */
  const toGraph = (vbX: number, vbY: number): { x: number; y: number } => {
    const t = transformRef.current;
    return { x: (vbX - t.tx) / t.k, y: (vbY - t.ty) / t.k };
  };

  // Zoom molette : listener natif non-passif pour pouvoir preventDefault.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent): void => {
      e.preventDefault();
      const vb = toViewBox(e.clientX, e.clientY);
      const t = transformRef.current;
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
      const k2 = clampZoom(t.k * factor);
      const px = (vb.x - t.tx) / t.k;
      const py = (vb.y - t.ty) / t.k;
      setTransform({ k: k2, tx: vb.x - k2 * px, ty: vb.y - k2 * py });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [height]);

  const onBackgroundPointerDown = (e: ReactPointerEvent): void => {
    svgRef.current?.setPointerCapture(e.pointerId);
    const vb = toViewBox(e.clientX, e.clientY);
    interactionRef.current = { mode: "pan", lastX: vb.x, lastY: vb.y };
  };

  const onNodePointerDown = (id: string) => (e: ReactPointerEvent): void => {
    e.stopPropagation();
    svgRef.current?.setPointerCapture(e.pointerId);
    const vb = toViewBox(e.clientX, e.clientY);
    startDrag(id);
    interactionRef.current = {
      mode: "node",
      id,
      lastX: vb.x,
      lastY: vb.y,
      downX: vb.x,
      downY: vb.y,
      moved: false,
    };
  };

  const onPointerMove = (e: ReactPointerEvent): void => {
    const it = interactionRef.current;
    if (it.mode === "none") return;
    const vb = toViewBox(e.clientX, e.clientY);
    if (it.mode === "pan") {
      const dx = vb.x - it.lastX;
      const dy = vb.y - it.lastY;
      setTransform((t) => ({ ...t, tx: t.tx + dx, ty: t.ty + dy }));
      it.lastX = vb.x;
      it.lastY = vb.y;
    } else {
      const g = toGraph(vb.x, vb.y);
      dragTo(it.id, g.x, g.y);
      if (Math.hypot(vb.x - it.downX, vb.y - it.downY) > CLICK_SLOP) it.moved = true;
      it.lastX = vb.x;
      it.lastY = vb.y;
    }
  };

  const onPointerUp = (e: ReactPointerEvent): void => {
    const it = interactionRef.current;
    svgRef.current?.releasePointerCapture?.(e.pointerId);
    if (it.mode === "node") {
      endDrag(it.id);
      if (!it.moved && onNodeClick) {
        const node = nodes.find((n) => n.id === it.id);
        if (node) onNodeClick(node);
      }
    }
    interactionRef.current = { mode: "none" };
  };

  if (nodes.length === 0) {
    return (
      <div
        className={cn(
          "flex items-center justify-center rounded-lg border border-border text-sm text-muted-foreground",
          className,
        )}
        style={{ height }}
      >
        {emptyMessage}
      </div>
    );
  }

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${VIEW_W} ${height}`}
      className={cn(
        "w-full touch-none select-none rounded-lg border border-border",
        className,
      )}
      style={{ height, backgroundColor: "var(--bg-tertiary)", cursor: "grab" }}
      onPointerDown={onBackgroundPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerLeave={onPointerUp}
    >
      <g transform={`translate(${transform.tx} ${transform.ty}) scale(${transform.k})`}>
        {links.map((link, i) => {
          const a = posById.get(link.source);
          const b = posById.get(link.target);
          if (!a || !b) return null;
          return (
            <line
              key={`${link.source}-${link.target}-${i}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={link.color ?? "rgba(148, 163, 184, 0.35)"}
              strokeWidth={1}
            />
          );
        })}
        {nodes.map((node) => {
          const pos = posById.get(node.id);
          if (!pos) return null;
          const r = node.size ?? 9;
          const selected = node.id === selectedId;
          return (
            <g
              key={node.id}
              transform={`translate(${pos.x} ${pos.y})`}
              style={{ cursor: "pointer" }}
              onPointerDown={onNodePointerDown(node.id)}
            >
              <circle
                r={r}
                fill={node.color ?? "var(--accent-cyan)"}
                stroke={selected ? "#ffffff" : "rgba(10, 15, 26, 0.8)"}
                strokeWidth={selected ? 2.5 : 1.5}
              />
              {node.label && (
                <text
                  x={0}
                  y={r + 11}
                  textAnchor="middle"
                  fontSize={9}
                  fill="var(--text-secondary)"
                  style={{ pointerEvents: "none" }}
                >
                  {node.label}
                </text>
              )}
            </g>
          );
        })}
      </g>
    </svg>
  );
}

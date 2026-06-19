/**
 * Moteur de simulation force-directed — TypeScript pur, sans dépendance.
 *
 * Modèle physique classique : répulsion coulombienne entre nœuds (∝ 1/d²),
 * ressorts de Hooke sur les arêtes, gravité de centrage, et **amortissement**
 * de la vélocité pour garantir une convergence stable (ni vibration, ni
 * divergence). Framework-agnostique et testable : `stepSimulation` mute les
 * nœuds en place et renvoie l'énergie cinétique totale (utile pour détecter la
 * convergence côté appelant).
 *
 * Réutilisable par tout graphe du dashboard (M2 graphe réseau, M4 graphe de
 * clusters au Lot 3).
 */

/** Nœud de simulation (position + vélocité mutées en place). */
export interface SimNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  /** Rayon visuel — borne basse de distance pour la répulsion. */
  radius: number;
  /** Épinglé (position figée, ex. pendant un drag) : forces ignorées. */
  fixed?: boolean;
}

/** Arête de simulation, référencée par id de nœud. */
export interface SimLink {
  source: string;
  target: string;
  /** Multiplicateur de raideur du ressort (défaut 1). */
  strength?: number;
}

/** Entrée minimale pour initialiser un nœud. */
export interface SimNodeInput {
  id: string;
  radius?: number;
}

/** Paramètres réglables de la simulation. */
export interface ForceParams {
  width: number;
  height: number;
  /** Constante de répulsion (plus grand = nœuds plus écartés). */
  repulsion: number;
  /** Longueur au repos des ressorts. */
  springLength: number;
  /** Raideur des ressorts (0..1). */
  springStrength: number;
  /** Force d'attraction vers le centre (0..1). */
  centerGravity: number;
  /** Amortissement de la vélocité par pas (0..1, < 1 = convergence). */
  damping: number;
  /** Bornage de la vélocité par pas (anti-divergence). */
  maxVelocity: number;
}

/** Distance² minimale prise en compte (évite les forces explosives). */
const MIN_DIST_SQ = 100;
/** Marge des bords : les nœuds restent dans le cadre. */
const BOUNDS_MARGIN = 24;

/** Paramètres par défaut, calibrés pour quelques dizaines de nœuds. */
export function defaultForceParams(width: number, height: number): ForceParams {
  return {
    width,
    height,
    repulsion: 2400,
    springLength: 90,
    springStrength: 0.04,
    centerGravity: 0.02,
    damping: 0.85,
    maxVelocity: 28,
  };
}

/**
 * Initialise les nœuds sur un cercle autour du centre (déterministe, sans
 * chevauchement initial). Permet de réutiliser les positions existantes lors
 * d'un changement de topologie via `previous`.
 */
export function initNodes(
  inputs: SimNodeInput[],
  width: number,
  height: number,
  previous?: readonly SimNode[],
): SimNode[] {
  const cx = width / 2;
  const cy = height / 2;
  const ring = Math.min(width, height) * 0.35;
  const n = inputs.length;
  const prevById = new Map<string, SimNode>();
  for (const p of previous ?? []) prevById.set(p.id, p);

  return inputs.map((input, i) => {
    const kept = prevById.get(input.id);
    if (kept) {
      return { ...kept, radius: input.radius ?? kept.radius };
    }
    const angle = (i / Math.max(1, n)) * Math.PI * 2;
    return {
      id: input.id,
      x: cx + Math.cos(angle) * ring,
      y: cy + Math.sin(angle) * ring,
      vx: 0,
      vy: 0,
      radius: input.radius ?? 8,
    };
  });
}

function clamp(value: number, min: number, max: number): number {
  return value < min ? min : value > max ? max : value;
}

/**
 * Avance la simulation d'un pas (Euler amorti). Mute `nodes` en place et
 * renvoie l'énergie cinétique totale du système (Σ v²).
 */
export function stepSimulation(
  nodes: SimNode[],
  links: readonly SimLink[],
  p: ForceParams,
): number {
  const n = nodes.length;
  if (n === 0) return 0;

  const cx = p.width / 2;
  const cy = p.height / 2;
  const fx = new Array<number>(n).fill(0);
  const fy = new Array<number>(n).fill(0);
  const index = new Map<string, number>();
  for (let i = 0; i < n; i++) index.set(nodes[i].id, i);

  // Répulsion paire à paire (∝ 1/d²).
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      let dx = nodes[i].x - nodes[j].x;
      let dy = nodes[i].y - nodes[j].y;
      let distSq = dx * dx + dy * dy;
      if (distSq === 0) {
        // Superposition exacte : séparation déterministe.
        dx = (i - j) || 1;
        dy = 0;
        distSq = 1;
      }
      const effSq = Math.max(distSq, MIN_DIST_SQ);
      const dist = Math.sqrt(distSq);
      const force = p.repulsion / effSq;
      const ux = dx / dist;
      const uy = dy / dist;
      fx[i] += ux * force;
      fy[i] += uy * force;
      fx[j] -= ux * force;
      fy[j] -= uy * force;
    }
  }

  // Ressorts sur les arêtes (loi de Hooke).
  for (const link of links) {
    const si = index.get(link.source);
    const ti = index.get(link.target);
    if (si === undefined || ti === undefined) continue;
    const dx = nodes[ti].x - nodes[si].x;
    const dy = nodes[ti].y - nodes[si].y;
    const dist = Math.hypot(dx, dy) || 0.01;
    const displacement = dist - p.springLength;
    const force = p.springStrength * displacement * (link.strength ?? 1);
    const ux = dx / dist;
    const uy = dy / dist;
    fx[si] += ux * force;
    fy[si] += uy * force;
    fx[ti] -= ux * force;
    fy[ti] -= uy * force;
  }

  // Gravité de centrage + intégration amortie.
  let energy = 0;
  for (let i = 0; i < n; i++) {
    const node = nodes[i];
    if (node.fixed) {
      node.vx = 0;
      node.vy = 0;
      continue;
    }
    fx[i] += (cx - node.x) * p.centerGravity;
    fy[i] += (cy - node.y) * p.centerGravity;

    let vx = (node.vx + fx[i]) * p.damping;
    let vy = (node.vy + fy[i]) * p.damping;
    const speed = Math.hypot(vx, vy);
    if (speed > p.maxVelocity) {
      vx = (vx / speed) * p.maxVelocity;
      vy = (vy / speed) * p.maxVelocity;
    }
    node.vx = vx;
    node.vy = vy;
    node.x = clamp(node.x + vx, BOUNDS_MARGIN, p.width - BOUNDS_MARGIN);
    node.y = clamp(node.y + vy, BOUNDS_MARGIN, p.height - BOUNDS_MARGIN);
    energy += vx * vx + vy * vy;
  }

  return energy;
}

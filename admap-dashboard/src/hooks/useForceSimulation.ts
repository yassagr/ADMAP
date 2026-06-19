/**
 * Hook React pilotant `lib/forceSimulation` via `requestAnimationFrame`.
 *
 * Gère le cycle de vie de la boucle d'animation : (re)construit les nœuds quand
 * la topologie change (en réutilisant les positions des nœuds conservés pour
 * éviter les sauts), s'arrête automatiquement à convergence (énergie sous seuil
 * pendant plusieurs frames) et au démontage. Expose un **snapshot d'état** des
 * positions (rendu) + des handlers de drag qui épinglent le nœud manipulé.
 *
 * Les refs (tableau mutable, rAF, params) ne sont touchées que dans des effets
 * ou des callbacks — jamais pendant le render (règle `react-hooks/refs`).
 *
 * Réutilisable par tout graphe (M2 réseau, M4 clusters). Aucune dépendance.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import {
  defaultForceParams,
  initNodes,
  stepSimulation,
  type ForceParams,
  type SimLink,
  type SimNode,
  type SimNodeInput,
} from "@/lib/forceSimulation";

/** Énergie cinétique moyenne par nœud sous laquelle on considère le calme. */
const CALM_ENERGY = 0.05;
/** Nombre de frames calmes consécutives avant d'arrêter la boucle. */
const CALM_FRAMES = 30;

export interface UseForceSimulationResult {
  /** Snapshot des nœuds positionnés (état de rendu, recopié à chaque frame). */
  nodes: SimNode[];
  /** Épingle un nœud (début de drag). */
  startDrag: (id: string) => void;
  /** Déplace un nœud épinglé sous le curseur. */
  dragTo: (id: string, x: number, y: number) => void;
  /** Relâche le nœud (fin de drag). */
  endDrag: (id: string) => void;
  /** Relance la boucle (après un changement externe de positions). */
  reheat: () => void;
}

export function useForceSimulation(
  inputs: SimNodeInput[],
  links: SimLink[],
  width: number,
  height: number,
  paramsOverride?: Partial<ForceParams>,
): UseForceSimulationResult {
  const workingRef = useRef<SimNode[]>([]); // tableau muté par la simulation
  const linksRef = useRef<readonly SimLink[]>([]);
  const paramsRef = useRef<ForceParams>(defaultForceParams(width, height));
  const rafRef = useRef<number | null>(null);
  const calmRef = useRef(0);
  const reheatRef = useRef<() => void>(() => {});
  const [nodes, setNodes] = useState<SimNode[]>([]);

  // Clés stables de topologie : relancent l'effet uniquement si elle change.
  const nodeKey = inputs.map((n) => n.id).join("|");
  const linkKey = links.map((l) => `${l.source}>${l.target}`).join("|");

  // Synchronise arêtes/params dans des refs APRÈS render (effet sans deps).
  useEffect(() => {
    linksRef.current = links;
    paramsRef.current = { ...defaultForceParams(width, height), ...paramsOverride };
  });

  // (Re)construction de la topologie + boucle d'animation.
  useEffect(() => {
    workingRef.current = initNodes(inputs, width, height, workingRef.current);
    calmRef.current = 0;

    const tick = (): void => {
      const energy = stepSimulation(
        workingRef.current,
        linksRef.current,
        paramsRef.current,
      );
      setNodes(workingRef.current.map((n) => ({ ...n })));
      const avg = energy / Math.max(1, workingRef.current.length);
      calmRef.current = avg < CALM_ENERGY ? calmRef.current + 1 : 0;
      rafRef.current =
        calmRef.current < CALM_FRAMES ? requestAnimationFrame(tick) : null;
    };
    const start = (): void => {
      if (rafRef.current === null) rafRef.current = requestAnimationFrame(tick);
    };
    reheatRef.current = (): void => {
      calmRef.current = 0;
      start();
    };

    setNodes(workingRef.current.map((n) => ({ ...n })));
    start();

    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
    // Topologie + dimensions seulement : `inputs`/`links` relus via refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeKey, linkKey, width, height]);

  const startDrag = useCallback((id: string): void => {
    const node = workingRef.current.find((n) => n.id === id);
    if (node) {
      node.fixed = true;
      node.vx = 0;
      node.vy = 0;
    }
    reheatRef.current();
  }, []);

  const dragTo = useCallback((id: string, x: number, y: number): void => {
    const node = workingRef.current.find((n) => n.id === id);
    if (node) {
      node.x = x;
      node.y = y;
      node.vx = 0;
      node.vy = 0;
    }
    reheatRef.current();
  }, []);

  const endDrag = useCallback((id: string): void => {
    const node = workingRef.current.find((n) => n.id === id);
    if (node) node.fixed = false;
    reheatRef.current();
  }, []);

  const reheat = useCallback((): void => reheatRef.current(), []);

  return { nodes, startDrag, dragTo, endDrag, reheat };
}

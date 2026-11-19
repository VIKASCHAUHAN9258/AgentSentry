import {
  BufferGeometry,
  Float32BufferAttribute,
  Group,
  IcosahedronGeometry,
  Line,
  LineBasicMaterial,
  MathUtils,
  Mesh,
  MeshBasicMaterial,
  PerspectiveCamera,
  Points,
  PointsMaterial,
  QuadraticBezierCurve3,
  Raycaster,
  RingGeometry,
  Scene,
  SphereGeometry,
  Vector2,
  Vector3,
  WebGLRenderer,
} from "three";
import type { SessionSummary } from "../../api/types";

export interface NetworkTopologyNode {
  session: SessionSummary;
  position: [number, number, number];
  severity: string | null;
}

export interface NetworkTopologyController {
  updateNodes(nodes: NetworkTopologyNode[]): void;
  dispose(): void;
}

function severityColor(severity: string | null): number {
  if (severity === "CRITICAL") return 0xfb7185;
  if (severity === "HIGH") return 0xf6ad55;
  return 0x58d9dc;
}

function connectionGeometry(position: [number, number, number]): BufferGeometry {
  const start = new Vector3(0, 0, 0);
  const end = new Vector3(...position);
  const control = start.clone().lerp(end, 0.5);
  control.y += 0.25 + Math.abs(position[0]) * 0.08;
  return new BufferGeometry().setFromPoints(
    new QuadraticBezierCurve3(start, control, end).getPoints(24),
  );
}

export function mountNetworkTopology(
  host: HTMLElement,
  nodes: NetworkTopologyNode[],
  onHover: (session: SessionSummary | null) => void,
  onSelect: (session: SessionSummary) => void,
): NetworkTopologyController {
  const renderer = new WebGLRenderer({
    alpha: true,
    antialias: false,
    powerPreference: "low-power",
  });
  const scene = new Scene();
  const camera = new PerspectiveCamera(42, 1, 0.1, 40);
  camera.position.set(0, 0, 7.3);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.25));
  renderer.setClearColor(0x000000, 0);
  renderer.domElement.setAttribute(
    "aria-label",
    "Interactive visualization of recorded AgentSentry sessions",
  );
  renderer.domElement.setAttribute("role", "img");
  renderer.domElement.tabIndex = 0;
  host.appendChild(renderer.domElement);

  const root = new Group();
  scene.add(root);
  const nodeGeometry = new SphereGeometry(0.075, 10, 8);
  const core = new Mesh(
    new IcosahedronGeometry(0.46, 2),
    new MeshBasicMaterial({
      color: 0x063c35,
      wireframe: true,
      transparent: true,
      opacity: 0.82,
    }),
  );
  const coreGlow = new Mesh(
    new SphereGeometry(0.29, 16, 12),
    new MeshBasicMaterial({ color: 0x00b995, transparent: true, opacity: 0.19 }),
  );
  root.add(core, coreGlow);

  const rings: Mesh[] = [];
  for (let index = 0; index < 3; index += 1) {
    const ring = new Mesh(
      new RingGeometry(1.2 + index * 0.34, 1.205 + index * 0.34, 72),
      new MeshBasicMaterial({
        color: index === 1 ? 0x00a98a : 0x087d6a,
        transparent: true,
        opacity: 0.35,
        side: 2,
      }),
    );
    ring.rotation.x = Math.PI / 2 + index * 0.12;
    ring.rotation.y = index * 0.4;
    root.add(ring);
    rings.push(ring);
  }

  const gridPositions: number[] = [];
  for (let index = -5; index <= 5; index += 1) {
    const offset = index * 0.48;
    gridPositions.push(-5, -1.55, offset, 5, -1.55, offset);
    gridPositions.push(offset, -1.55, -5, offset, -1.55, 5);
  }
  const gridGeometry = new BufferGeometry();
  gridGeometry.setAttribute(
    "position",
    new Float32BufferAttribute(gridPositions, 3),
  );
  const grid = new Line(
    gridGeometry,
    new LineBasicMaterial({
      color: 0x08745f,
      transparent: true,
      opacity: 0.19,
    }),
  );
  root.add(grid);

  const particleCount = 72;
  const particlePositions = new Float32Array(particleCount * 3);
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let index = 0; index < particleCount; index += 1) {
    const angle = index * goldenAngle;
    const radius = 2.1 + ((index * 37) % 100) / 100 * 2.6;
    particlePositions[index * 3] = Math.cos(angle) * radius;
    particlePositions[index * 3 + 1] = (((index * 53) % 100) / 100 - 0.5) * 3.1;
    particlePositions[index * 3 + 2] = Math.sin(angle) * radius;
  }
  const particleGeometry = new BufferGeometry();
  particleGeometry.setAttribute(
    "position",
    new Float32BufferAttribute(particlePositions, 3),
  );
  const particles = new Points(
    particleGeometry,
    new PointsMaterial({
      color: 0x20d9b4,
      size: 0.025,
      transparent: true,
      opacity: 0.58,
      sizeAttenuation: true,
    }),
  );
  root.add(particles);

  const nodeRecords = new Map<
    string,
    { mesh: Mesh; line: Line; data: NetworkTopologyNode }
  >();
  let hoveredSessionId: string | null = null;
  let activePointer: { id: number; x: number; y: number } | null = null;
  let suppressClick = false;
  const updateNodes = (nextNodes: NetworkTopologyNode[]) => {
    const nextById = new Map(nextNodes.map((data) => [data.session.session_id, data]));
    for (const [sessionId, record] of nodeRecords) {
      if (nextById.has(sessionId)) continue;
      root.remove(record.mesh, record.line);
      (record.mesh.material as MeshBasicMaterial).dispose();
      record.line.geometry.dispose();
      (record.line.material as LineBasicMaterial).dispose();
      nodeRecords.delete(sessionId);
      if (hoveredSessionId === sessionId) {
        hoveredSessionId = null;
        onHover(null);
      }
    }

    for (const data of nextNodes) {
      const sessionId = data.session.session_id;
      const color = severityColor(data.severity);
      const existing = nodeRecords.get(sessionId);
      if (existing) {
        existing.data = data;
        existing.mesh.position.set(...data.position);
        (existing.mesh.material as MeshBasicMaterial).color.setHex(color);
        const lineMaterial = existing.line.material as LineBasicMaterial;
        lineMaterial.color.setHex(color);
        lineMaterial.opacity = data.severity ? 0.68 : 0.42;
        existing.line.geometry.dispose();
        existing.line.geometry = connectionGeometry(data.position);
        continue;
      }

      const mesh = new Mesh(
        nodeGeometry,
        new MeshBasicMaterial({ color }),
      );
      mesh.position.set(...data.position);
      const line = new Line(
        connectionGeometry(data.position),
        new LineBasicMaterial({
          color,
          transparent: true,
          opacity: data.severity ? 0.68 : 0.42,
        }),
      );
      root.add(mesh, line);
      nodeRecords.set(sessionId, { mesh, line, data });
    }
    if (hoveredSessionId !== null) {
      const current = nodeRecords.get(hoveredSessionId);
      if (current) onHover(current.data.session);
    }
    renderer.render(scene, camera);
  };

  updateNodes(nodes);

  const resize = () => {
    const width = Math.max(host.clientWidth, 1);
    const height = Math.max(host.clientHeight, 1);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
    renderer.render(scene, camera);
  };
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(host);
  resize();

  const raycaster = new Raycaster();
  const pointer = new Vector2();
  const onPointerDown = (event: PointerEvent) => {
    activePointer = { id: event.pointerId, x: event.clientX, y: event.clientY };
    renderer.domElement.setPointerCapture(event.pointerId);
    suppressClick = false;
  };
  const onPointerMove = (event: PointerEvent) => {
    if (activePointer?.id === event.pointerId) {
      const deltaX = event.clientX - activePointer.x;
      const deltaY = event.clientY - activePointer.y;
      if (Math.abs(deltaX) + Math.abs(deltaY) > 2) suppressClick = true;
      root.rotation.y += deltaX * 0.006;
      root.rotation.x += deltaY * 0.006;
      activePointer.x = event.clientX;
      activePointer.y = event.clientY;
      renderer.render(scene, camera);
      return;
    }
    const bounds = renderer.domElement.getBoundingClientRect();
    pointer.set(
      ((event.clientX - bounds.left) / bounds.width) * 2 - 1,
      -((event.clientY - bounds.top) / bounds.height) * 2 + 1,
    );
    raycaster.setFromCamera(pointer, camera);
    const records = Array.from(nodeRecords.values());
    const [hit] = raycaster.intersectObjects(records.map(({ mesh }) => mesh));
    const selected = records.find(({ mesh }) => mesh === hit?.object)?.data.session ?? null;
    const nextHoveredId = selected?.session_id ?? null;
    if (nextHoveredId !== hoveredSessionId) {
      hoveredSessionId = nextHoveredId;
      onHover(selected);
    }
  };
  const onPointerUp = (event: PointerEvent) => {
    if (activePointer?.id === event.pointerId) {
      activePointer = null;
      if (renderer.domElement.hasPointerCapture(event.pointerId)) {
        renderer.domElement.releasePointerCapture(event.pointerId);
      }
    }
  };
  const onKeyDown = (event: KeyboardEvent) => {
    const step = 0.12;
    if (event.key === "ArrowLeft") root.rotation.y -= step;
    else if (event.key === "ArrowRight") root.rotation.y += step;
    else if (event.key === "ArrowUp") root.rotation.x -= step;
    else if (event.key === "ArrowDown") root.rotation.x += step;
    else return;
    event.preventDefault();
    renderer.render(scene, camera);
  };
  const onClick = (event: MouseEvent) => {
    if (suppressClick) {
      suppressClick = false;
      return;
    }
    const bounds = renderer.domElement.getBoundingClientRect();
    pointer.set(
      ((event.clientX - bounds.left) / bounds.width) * 2 - 1,
      -((event.clientY - bounds.top) / bounds.height) * 2 + 1,
    );
    raycaster.setFromCamera(pointer, camera);
    const records = Array.from(nodeRecords.values());
    const [hit] = raycaster.intersectObjects(records.map(({ mesh }) => mesh));
    const selected = records.find(({ mesh }) => mesh === hit?.object)?.data.session;
    if (selected) onSelect(selected);
  };
  const onWheel = (event: WheelEvent) => {
    event.preventDefault();
    camera.position.z = MathUtils.clamp(camera.position.z + event.deltaY * 0.004, 4.5, 10);
    renderer.render(scene, camera);
  };
  renderer.domElement.addEventListener("pointerdown", onPointerDown);
  renderer.domElement.addEventListener("pointermove", onPointerMove);
  renderer.domElement.addEventListener("pointerup", onPointerUp);
  renderer.domElement.addEventListener("pointercancel", onPointerUp);
  renderer.domElement.addEventListener("keydown", onKeyDown);
  renderer.domElement.addEventListener("click", onClick);
  renderer.domElement.addEventListener("wheel", onWheel, { passive: false });

  let isIntersecting = false;
  const intersectionObserver = new IntersectionObserver(([entry]) => {
    isIntersecting = entry?.isIntersecting ?? false;
    syncAnimation();
  });
  intersectionObserver.observe(host);
  const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
  let frameId = 0;
  let lastFrameTime = 0;
  let disposed = false;
  const canAnimate = () =>
    !disposed &&
    document.visibilityState === "visible" &&
    isIntersecting &&
    !motionPreference.matches;
  const animate = (time: number) => {
    frameId = 0;
    if (!canAnimate()) return;
    if (time - lastFrameTime >= 40) {
      lastFrameTime = time;
      core.rotation.y += 0.002;
      core.rotation.x += 0.0007;
      rings.forEach((ring, index) => {
        ring.rotation.z += index % 2 ? 0.0008 : -0.00065;
      });
      particles.rotation.y += 0.00025;
      renderer.render(scene, camera);
    }
    frameId = window.requestAnimationFrame(animate);
  };
  const syncAnimation = () => {
    if (canAnimate()) {
      if (frameId === 0) frameId = window.requestAnimationFrame(animate);
    } else if (frameId !== 0) {
      window.cancelAnimationFrame(frameId);
      frameId = 0;
    }
  };
  const onVisibilityChange = () => syncAnimation();
  document.addEventListener("visibilitychange", onVisibilityChange);
  motionPreference.addEventListener("change", syncAnimation);

  return {
    updateNodes,
    dispose() {
      disposed = true;
      if (frameId !== 0) window.cancelAnimationFrame(frameId);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      document.removeEventListener("visibilitychange", onVisibilityChange);
      motionPreference.removeEventListener("change", syncAnimation);
      renderer.domElement.removeEventListener("pointerdown", onPointerDown);
      renderer.domElement.removeEventListener("pointermove", onPointerMove);
      renderer.domElement.removeEventListener("pointerup", onPointerUp);
      renderer.domElement.removeEventListener("pointercancel", onPointerUp);
      renderer.domElement.removeEventListener("keydown", onKeyDown);
      renderer.domElement.removeEventListener("click", onClick);
      renderer.domElement.removeEventListener("wheel", onWheel);
      if (activePointer && renderer.domElement.hasPointerCapture(activePointer.id)) {
        renderer.domElement.releasePointerCapture(activePointer.id);
      }
      nodeRecords.clear();
      const geometries = new Set<BufferGeometry>();
      const materials = new Set<MeshBasicMaterial | LineBasicMaterial | PointsMaterial>();
      root.traverse((object) => {
        if (!(object instanceof Mesh || object instanceof Line || object instanceof Points)) {
          return;
        }
        geometries.add(object.geometry);
        const objectMaterials = Array.isArray(object.material)
          ? object.material
          : [object.material];
        for (const material of objectMaterials) {
          materials.add(material as MeshBasicMaterial | LineBasicMaterial | PointsMaterial);
        }
      });
      geometries.forEach((geometry) => geometry.dispose());
      materials.forEach((material) => material.dispose());
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}

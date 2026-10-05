// 3D wireframe radar dish for the popup header.
//
// PRESENTATION ONLY. This module renders a decorative, purely graphical element.
// It reads the existing threat state and changes nothing about it: it never
// computes, requests, or alters a verdict, a score, or a decision.
//
// Structure:
//   .radar3d              outer box (perspective + sizing)
//     .radar3d__scene     3D scene container (preserve-3d)
//       .radar3d__dish    rotating 3D axis assembly
//         .radar3d__face--front  front 3/4 perspective artwork from reference
//         .radar3d__face--back   back 3/4 perspective artwork from reference
//     .radar3d__glow      ambient state glow halo

/**
 * Returns the radar's markup.
 *
 * @returns {string} HTML for the radar element.
 */
export function radarMarkup() {
  const spars = Array.from(
    { length: 12 },
    (_, i) => `<i class="radar3d__wire" style="transform:rotateY(${i * 30}deg)"></i>`,
  ).join("");

  return `
<div class="radar3d" aria-hidden="true" role="presentation">
  <div class="radar3d__scene">
    <div class="radar3d__dish">
      <div class="radar3d__face radar3d__face--front"></div>
      <div class="radar3d__face radar3d__face--back"></div>
    </div>
  </div>
  <div class="radar3d__glow"></div>
  <div class="radar3d__mount" style="display:none">
    <i class="radar3d__neck"></i>
    <i class="radar3d__pedestal"></i>
  </div>
  <div class="radar3d__cone" style="display:none">${spars}</div>
  <div class="radar3d__rim" style="display:none"></div>
  <div class="radar3d__hub" style="display:none"></div>
  <div class="radar3d__feed" style="display:none"></div>
  <div class="radar3d__sweep" style="display:none"></div>
</div>`.trim();
}

/**
 * Applies a threat state to a radar element.
 *
 * @param {HTMLElement|null} element - The radar container (.radar3d).
 * @param {string} state - A threat state value, or "off".
 * @returns {string} The state that was applied.
 */
export function setRadarState(element, state) {
  const value = typeof state === "string" && state ? state : "secure";
  if (element && typeof element.setAttribute === "function") {
    element.dataset.state = value;
  }
  return value;
}

/**
 * Mounts the radar into a host element, replacing any previous instance.
 *
 * @param {HTMLElement|null} host - Element to render into.
 * @returns {HTMLElement|null} The mounted radar element, or null on failure.
 */
export function mountRadar(host) {
  if (!host || typeof host.innerHTML !== "string") {
    return null;
  }
  host.innerHTML = radarMarkup();
  if (typeof host.querySelector !== "function") {
    return null;
  }
  return host.querySelector(".radar3d");
}

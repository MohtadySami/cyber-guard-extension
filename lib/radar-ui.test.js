// The 3D radar header component. Presentation only: these tests assert markup
// and state mapping, and that the module never touches anything security-related.

import test from "node:test";
import assert from "node:assert/strict";

import { radarMarkup, setRadarState, mountRadar } from "./radar-ui.js";

test("markup renders the dish parts the CSS animates", () => {
  const html = radarMarkup();
  // Core dish parts that drive the CSS animation
  for (const part of [
    "radar3d",
    "radar3d__dish",
    "radar3d__cone",
    "radar3d__rim",
    "radar3d__hub",
    "radar3d__feed",
    "radar3d__sweep",
  ]) {
    assert.ok(html.includes(part), `missing ${part}`);
  }
  // Stationary mount assembly (pedestal replaces the old flat base)
  for (const part of ["radar3d__mount", "radar3d__neck", "radar3d__pedestal"]) {
    assert.ok(html.includes(part), `missing mount part: ${part}`);
  }
});

test("the cone has enough wires to read as a 3D form", () => {
  const wires = (radarMarkup().match(/radar3d__wire/g) || []).length;
  // 12 spars give a convincing dish silhouette across the full 360° rotation
  assert.ok(wires >= 12, `expected at least 12 cone spars, found ${wires}`);
});

test("markup is decorative and hidden from assistive tech", () => {
  assert.ok(radarMarkup().includes('aria-hidden="true"'));
});

test("markup contains no images, scripts or remote references", () => {
  const html = radarMarkup();
  const forbidden = ["<img", "<script", "http://", "https://", "url(", "@import"];
  for (const token of forbidden) {
    assert.equal(html.includes(token), false, `markup must not contain ${token}`);
  }
});

// --- State mapping (presentation only)

/**
 * Minimal stand-in for an element: mirrors the DOM behaviour the component
 * relies on (dataset is written through setAttribute("data-...")).
 */
function fakeElement() {
  const attributes = new Map();
  return {
    attributes,
    setAttribute(name, value) {
      attributes.set(name, value);
    },
    get dataset() {
      const self = this;
      return new Proxy(
        {},
        {
          get: (_t, key) => self.attributes.get(`data-${key}`),
          set: (_t, key, value) => {
            self.attributes.set(`data-${key}`, value);
            return true;
          },
        },
      );
    },
  };
}

test("setRadarState writes the state onto the element", () => {
  const element = fakeElement();
  assert.equal(setRadarState(element, "threat"), "threat");
  assert.equal(element.attributes.get("data-state"), "threat");
});

test("setRadarState accepts every threat state and off", () => {
  for (const state of ["secure", "analyzing", "threat", "off"]) {
    const element = fakeElement();
    setRadarState(element, state);
    assert.equal(element.attributes.get("data-state"), state);
  }
});

test("setRadarState defaults to secure for missing input", () => {
  for (const bad of [undefined, null, "", 0, false, 42]) {
    const element = fakeElement();
    assert.equal(setRadarState(element, bad), "secure");
    assert.equal(element.attributes.get("data-state"), "secure");
  }
});

test("setRadarState tolerates a missing element", () => {
  assert.equal(setRadarState(null, "threat"), "threat");
  assert.doesNotThrow(() => setRadarState(undefined, "analyzing"));
});

test("setRadarState performs no analysis and reads no settings", () => {
  // Guard against the component ever growing decision logic: it takes only an
  // element and a state string, so it cannot compute or alter a verdict.
  assert.equal(setRadarState.length, 2);
  const source = setRadarState.toString();
  const forbidden = ["evaluate", "score", "verdict", "chrome.", "fetch", "storage"];
  for (const token of forbidden) {
    assert.equal(source.includes(token), false, `setRadarState must not reference ${token}`);
  }
});

// --- Mounting

test("mountRadar injects the markup and returns the radar element", () => {
  const host = { innerHTML: "" };
  const radar = { className: "radar3d" };
  host.querySelector = (selector) => (selector === ".radar3d" ? radar : null);

  assert.equal(mountRadar(host), radar, "callers need the radar node to apply state to");
  assert.ok(host.innerHTML.includes("radar3d__dish"));
});

test("mountRadar returns null when the radar element cannot be resolved", () => {
  const host = { innerHTML: "", querySelector: () => null };
  assert.equal(mountRadar(host), null);
});

test("mountRadar replaces any previous instance", () => {
  const host = { innerHTML: "<div>old radar</div>" };
  mountRadar(host);
  assert.equal(host.innerHTML.includes("old radar"), false);
});

test("mountRadar tolerates a missing host", () => {
  assert.equal(mountRadar(null), null);
  assert.equal(mountRadar(undefined), null);
  assert.equal(mountRadar({}), null);
  assert.equal(mountRadar({ innerHTML: "" }), null, "no querySelector -> null");
});

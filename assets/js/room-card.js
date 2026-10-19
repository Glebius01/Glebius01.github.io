// writeup-cards: renders a room / machine info card from the JSON that
// writeup_cards.py saves. Plain ES module with no dependencies: use it in
// Node at build time or in the browser. Returns an HTML string; every value
// taken from the data is escaped here. Style it with room-card.css.
//
//   import { roomCardHtml } from "./room-card.js";
//   html = roomCardHtml(meta, { iconBase: "/meta/thm/" });
//
// MIT licence. https://github.com/paracausaltelemetry/writeup-cards

const esc = (value = "") =>
  String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

const shortDate = (iso, locale) => {
  const parsed = iso ? new Date(`${iso}T00:00:00Z`) : null;
  return parsed && !Number.isNaN(parsed.getTime())
    ? parsed.toLocaleDateString(locale, { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })
    : "";
};
const count = (n, locale) => (typeof n === "number" ? n.toLocaleString(locale) : "");
const titleCase = (s = "") => String(s).charAt(0).toUpperCase() + String(s).slice(1);
// links and icons must be http(s) or site-relative; anything else is dropped
const safeUrl = (url) => (typeof url === "string" && /^(https?:\/\/|\/(?!\/))/i.test(url.trim()) ? url.trim() : "");
const fact = (label, value) => (value ? `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>` : "");

/** Player-rated difficulty: ten vote buckets, easiest to hardest. */
export const difficultyBars = (buckets) => {
  if (!Array.isArray(buckets) || buckets.length !== 10 || !buckets.some((n) => n > 0)) return "";
  const max = Math.max(...buckets), w = 20, gap = 6, h = 64;
  const hues = [96, 96, 80, 70, 50, 38, 28, 16, 8, 0];
  const bars = buckets.map((n, i) => {
    const bh = Math.max(2, Math.round((n / max) * h));
    return `<rect x="${i * (w + gap)}" y="${h - bh}" width="${w}" height="${bh}" rx="2" fill="hsl(${hues[i]} 70% 55%)"><title>${Number(n)} votes</title></rect>`;
  }).join("");
  const total = buckets.reduce((a, b) => a + b, 0);
  return `<figure class="wc-chart"><figcaption>Rated difficulty</figcaption><svg viewBox="0 0 ${10 * (w + gap) - gap} ${h}" role="img" aria-label="Player-rated difficulty, ${total} votes from easiest to hardest">${bars}</svg></figure>`;
};

const RADAR_AXES = ["Enumeration", "Real-Life", "CVE", "Custom Exploitation", "CTF-Like"];

/** Radar graph out of 10: Enumeration, Real-Life, CVE, Custom Exploitation, CTF-Like. */
export const radarGraph = (values) => {
  if (!Array.isArray(values) || values.length !== 5) return "";
  const c = 110, r = 70, max = 10;
  const point = (i, v) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / 5;
    return [c + Math.cos(a) * r * (v / max), c + Math.sin(a) * r * (v / max)];
  };
  const ring = (v) => RADAR_AXES.map((_, i) => point(i, v).map((n) => n.toFixed(1)).join(",")).join(" ");
  const rings = [2.5, 5, 7.5, 10].map((v) => `<polygon points="${ring(v)}" class="wc-radar-ring"/>`).join("");
  const spokes = RADAR_AXES.map((_, i) => {
    const [x, y] = point(i, max);
    return `<line x1="${c}" y1="${c}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="wc-radar-ring"/>`;
  }).join("");
  const shape = values.map((v, i) => point(i, Math.max(0, Math.min(max, Number(v) || 0))).map((n) => n.toFixed(1)).join(",")).join(" ");
  const labels = RADAR_AXES.map((label, i) => {
    const [x, y] = point(i, max + 2.6);
    const anchor = x < c - 5 ? "end" : x > c + 5 ? "start" : "middle";
    return `<text x="${x.toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${anchor}">${esc(label)}</text>`;
  }).join("");
  const summary = RADAR_AXES.map((label, i) => `${label} ${Number(values[i]).toFixed(1)}`).join(", ");
  return `<figure class="wc-chart wc-radar"><figcaption>Player profile</figcaption><svg viewBox="-60 0 340 230" role="img" aria-label="Radar graph out of 10: ${esc(summary)}">${rings}${spokes}<polygon points="${shape}" class="wc-radar-shape"/>${labels}</svg></figure>`;
};

/**
 * The card for one room or machine.
 * @param {object} meta  A JSON file saved by writeup_cards.py.
 * @param {object} [options]
 * @param {string} [options.iconBase]  URL folder holding meta.icon (e.g. "/meta/thm/"); omit to show no icon.
 * @param {string} [options.locale]    Number and date locale (default "en-GB").
 * @param {string} [options.headingLevel]  Heading tag for the name (default "h2").
 */
export const roomCardHtml = (meta, options = {}) => {
  if (!meta || typeof meta !== "object") return "";
  const { iconBase, locale = "en-GB", headingLevel = "h2" } = options;
  const h = /^h[1-6]$/.test(headingLevel) ? headingLevel : "h2";
  const thm = meta.platform === "thm";
  const name = thm ? meta.title : meta.name;
  const difficulty = String(meta.difficulty || "").toLowerCase();
  const kicker = thm ? `TryHackMe ${meta.type === "challenge" ? "challenge" : "room"}` : `Hack The Box ${meta.kind || "machine"}`;
  const iconSrc = safeUrl(meta.iconSrc || (meta.icon && iconBase ? `${iconBase.replace(/\/?$/, "/")}${meta.icon}` : ""));
  const link = safeUrl(meta.url);
  const facts = thm
    ? [
        fact("Released", shortDate(meta.released, locale)),
        fact("Type", titleCase(meta.type)),
        fact("Time", meta.minutes ? `${meta.minutes} min` : ""),
        fact("Joined", count(meta.users, locale)),
        fact("Votes", count(meta.votes, locale)),
        fact("Access", meta.free === true ? "Free" : meta.free === false ? "Subscribers" : "")
      ]
    : [
        fact("Released", shortDate(meta.released, locale)),
        fact("Retired", meta.retiredOn ? shortDate(meta.retiredOn, locale) : meta.retired ? "Yes" : ""),
        fact("OS", meta.os),
        fact("Category", meta.category),
        fact(meta.makers?.length > 1 ? "Creators" : "Creator", (meta.makers || []).join(", ")),
        fact("Rating", typeof meta.stars === "number" ? `${meta.stars.toFixed(1)} / 5` : ""),
        fact("User owns", count(meta.userOwns, locale)),
        fact("Root owns", count(meta.rootOwns, locale)),
        fact("Solves", count(meta.solves, locale))
      ];
  const bloods = thm ? "" : [["User blood", meta.userBlood], ["Root blood", meta.rootBlood]]
    .filter(([, b]) => b && (b.user || b.time))
    .map(([label, b]) => `<div><dt>${label}</dt><dd>${esc([b.user, b.time].filter(Boolean).join(" · "))}</dd></div>`).join("");
  const charts = thm ? "" : `${difficultyBars(meta.ratedDifficulty)}${radarGraph(meta.radar)}`;
  const badge = difficulty ? `<span class="wc-badge" data-difficulty="${esc(difficulty.replace(/[^a-z]/g, ""))}">${esc(titleCase(difficulty))}</span>` : "";
  return `<section class="wc-card" data-platform="${thm ? "thm" : "htb"}" data-difficulty="${esc(difficulty.replace(/[^a-z]/g, ""))}" aria-label="${esc(kicker)} details">`
    + `<div class="wc-head${iconSrc ? " wc-has-icon" : ""}">${iconSrc ?`<img src="${esc(iconSrc)}" width="56" height="56" alt="" loading="lazy" decoding="async" />` : ""}`
    + `<div class="wc-title"><p class="wc-kicker">${esc(kicker)}</p><${h}>${esc(name)}</${h}>${meta.description ? `<p>${esc(meta.description)}</p>` : ""}</div>${badge}</div>`
    + `<dl class="wc-facts">${facts.join("")}${bloods}</dl>`
    + (charts ? `<div class="wc-charts">${charts}</div>` : "")
    + (link ? `<p class="wc-link"><a href="${esc(link)}" rel="noreferrer" target="_blank">Open on ${thm ? "TryHackMe" : "Hack The Box"}<span class="wc-vh"> (opens in a new tab)</span></a></p>` : "")
    + `</section>`;
};

export default roomCardHtml;

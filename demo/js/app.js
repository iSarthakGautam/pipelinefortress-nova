/* PipelineFortress demo deck. No dependencies. Keys: -> / space next, <- back, A attack, N notes, G overview, T timer reset, F fullscreen, Home/End. */
(function () {
  "use strict";
  var deck = document.getElementById("deck");
  var slides = Array.prototype.slice.call(document.querySelectorAll(".slide"));
  var rail = document.getElementById("rail");
  var token = document.getElementById("token");
  var fill = document.getElementById("railfill");
  var stations = Array.prototype.slice.call(document.querySelectorAll(".station"));
  var count = document.getElementById("count");
  var progress = document.getElementById("progress");
  var notesEl = document.getElementById("notes");
  var notesBody = document.getElementById("notesBody");
  var overview = document.getElementById("overview");
  var SPACING = 1128 / 7, X0 = 76;

  var cur = 0, step = 0, started = null, tick = null;

  // ---- fit the 1280x720 canvas to the window
  function fit() {
    var s = Math.min(window.innerWidth / 1280, window.innerHeight / 720);
    deck.style.transform = "scale(" + s + ")";
  }
  window.addEventListener("resize", fit);

  // ---- rail
  stations.forEach(function (st, i) { st.style.left = (X0 + i * SPACING) + "px"; });
  function setRailOn(root, s) {
    var tk = root.querySelector(".tokx"), fl = root.querySelector(".fill"), sts = root.querySelectorAll(".station");
    var idx = parseInt(s.getAttribute("data-rail"), 10), state = s.getAttribute("data-state") || "";
    tk.style.left = (X0 + idx * SPACING) + "px";
    fl.style.width = (idx * SPACING) + "px";
    fl.classList.toggle("blocked", state === "blocked");
    tk.className = "tokx" + (state === "blocked" ? " blocked" : state === "ok" ? " ok" : "");
    tk.textContent = state === "ok" ? "✓ merged" : "search.py";
    Array.prototype.forEach.call(sts, function (st, i) {
      st.style.left = (X0 + i * SPACING) + "px";
      st.className = "station" + (state === "ok" || i < idx ? " done" : i === idx ? (state === "blocked" ? " blocked" : " active") : "");
    });
  }
  function setRail(s) {
    if (s.getAttribute("data-rail") === null) { rail.classList.remove("show"); return; }
    rail.classList.add("show");
    setRailOn(rail, s);
  }

  // ---- steps
  function maxStep(s) {
    var m = 0;
    Array.prototype.forEach.call(s.querySelectorAll("[data-step]"), function (e) { m = Math.max(m, +e.getAttribute("data-step")); });
    Array.prototype.forEach.call(s.querySelectorAll("[data-hide]"), function (e) { m = Math.max(m, +e.getAttribute("data-hide")); });
    Array.prototype.forEach.call(s.querySelectorAll("[data-autorun]"), function (e) { m = Math.max(m, +e.getAttribute("data-autorun")); });
    return m;
  }
  function typeInto(el) {
    if (el.dataset.typed) return;
    el.dataset.typed = "1";
    var full = el.getAttribute("data-text") || el.textContent;
    el.setAttribute("data-text", full);
    el.textContent = "";
    el.classList.add("typing");
    var i = 0;
    var t = setInterval(function () {
      i += 2;
      el.textContent = full.slice(0, i);
      if (i >= full.length) { clearInterval(t); el.classList.remove("typing"); }
    }, 16);
  }
  function applySteps(s, n, replay) {
    Array.prototype.forEach.call(s.querySelectorAll("[data-step]"), function (e) {
      var on = n >= +e.getAttribute("data-step");
      var was = e.classList.contains("on");
      e.classList.toggle("on", on);
      if (on && !was) {
        Array.prototype.forEach.call(e.querySelectorAll(".type"), typeInto);
        if (e.classList.contains("type")) typeInto(e);
      }
    });
    Array.prototype.forEach.call(s.querySelectorAll("[data-hide]"), function (e) {
      e.classList.toggle("off", n >= +e.getAttribute("data-hide"));
    });
    Array.prototype.forEach.call(s.querySelectorAll(".iso, .cube, .agent"), function (e) {
      var at = e.getAttribute("data-flat-at"); if (at) e.classList.toggle("flat", n >= +at);
      var go = e.getAttribute("data-go-at");
      if (go && e.classList.contains("cube")) { e.style.left = n >= +go ? e.getAttribute("data-to") : e.getAttribute("data-from"); }
      var enter = e.getAttribute("data-enter-at");
      if (enter) e.classList.toggle("enter", n < +enter);
    });
    Array.prototype.forEach.call(s.querySelectorAll(".plate[data-lit-at]"), function (p) {
      var a = +p.getAttribute("data-lit-at"), b = +(p.getAttribute("data-lit-until") || 99);
      p.classList.toggle("lit", n >= a && n < b);
      p.classList.toggle("bad", p.hasAttribute("data-bad-at") && n >= +p.getAttribute("data-bad-at"));
    });
    Array.prototype.forEach.call(s.querySelectorAll(".attackbox[data-autorun]"), function (a) {
      if (n >= +a.getAttribute("data-autorun") && !a.dataset.ran) runAttack(a);
    });
    var cube = s.querySelector(".cube");
    if (cube && cube.getAttribute("data-bad-at")) cube.classList.toggle("bad", n >= +cube.getAttribute("data-bad-at"));
  }

  // ---- attack
  function runAttack(box) {
    box.classList.remove("run");
    void box.offsetWidth;
    box.classList.add("run");
    box.dataset.ran = "1";
  }
  function attack() {
    var box = slides[cur].querySelector(".attackbox");
    if (box) runAttack(box); else { deck.classList.add("flash"); setTimeout(function () { deck.classList.remove("flash"); }, 600); }
  }

  // ---- navigation
  function show(i, n) {
    i = Math.max(0, Math.min(slides.length - 1, i));
    slides.forEach(function (s, k) {
      s.classList.toggle("current", k === i);
      s.classList.toggle("past", k < i);
    });
    cur = i; step = n || 0;
    var s = slides[cur];
    s.classList.toggle("has-rail", s.hasAttribute("data-rail"));
    setRail(s);
    if (step === 0) { Array.prototype.forEach.call(s.querySelectorAll(".attackbox"), function (a) { a.classList.remove("run"); delete a.dataset.ran; }); }
    applySteps(s, step);
    Array.prototype.forEach.call(document.querySelectorAll(".attackbtn"), function (b) { b.classList.toggle("hidden", !s.querySelector(".attackbox")); });
    count.textContent = (cur + 1) + " / " + slides.length;
    progress.style.width = ((cur + 1) / slides.length * 100) + "%";
    history.replaceState(null, "", "#" + (cur + 1));
    renderNotes();
  }
  function next() {
    if (!started) startTimer();
    var s = slides[cur];
    if (step < maxStep(s)) { step++; applySteps(s, step); renderNotes(); }
    else if (cur < slides.length - 1) show(cur + 1, 0);
  }
  function prev() {
    if (step > 0) { step--; applySteps(slides[cur], step); renderNotes(); }
    else if (cur > 0) show(cur - 1, maxStep(slides[cur - 1]));
  }

  // ---- notes + timer
  function fmt(sec) { sec = Math.max(0, Math.round(sec)); return Math.floor(sec / 60) + ":" + ("0" + (sec % 60)).slice(-2); }
  function startTimer() { started = Date.now(); clearInterval(tick); tick = setInterval(renderNotes, 1000); }
  function renderNotes() {
    var s = slides[cur], note = s.querySelector(".notes");
    var tgt = 0, upto = 0;
    slides.forEach(function (x, k) { var t = +(x.getAttribute("data-time") || 0); tgt += t; if (k <= cur) upto += t; });
    var el = started ? (Date.now() - started) / 1000 : 0;
    var delta = el - upto;
    notesBody.innerHTML =
      '<h4>Slide ' + (cur + 1) + ' · ' + (s.getAttribute("data-title") || "") + '</h4>' +
      '<div class="timer">' + fmt(el) + '</div>' +
      '<div class="tgt">target at end of this slide ' + fmt(upto) + ' of ' + fmt(tgt) + (started ? ' · ' + (delta > 15 ? '<span style="color:#fb4a68">' + fmt(delta) + ' behind</span>' : delta < -15 ? '<span style="color:#34d399">' + fmt(-delta) + ' ahead</span>' : 'on pace') : ' · timer starts on first →') + '</div><br>' +
      (note ? note.innerHTML : "<p class='dim'>No notes for this slide.</p>");
  }

  // ---- overview
  function buildOverview() {
    var h = '<h2>All slides <span class="dim" style="font-size:16px">(click to jump · G to close)</span></h2><div class="grid">';
    slides.forEach(function (s, i) {
      h += '<div class="item" data-i="' + i + '"><b>' + (i + 1) + '</b>' + (s.getAttribute("data-title") || "") + '<small>' + (s.getAttribute("data-time") || 0) + ' s</small></div>';
    });
    overview.innerHTML = h + "</div>";
    Array.prototype.forEach.call(overview.querySelectorAll(".item"), function (it) {
      it.addEventListener("click", function () { overview.classList.remove("show"); show(+it.getAttribute("data-i"), 0); });
    });
  }

  // ---- input
  document.addEventListener("keydown", function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var t = e.target && e.target.tagName;
    if (t === "INPUT" || t === "TEXTAREA" || (e.target && e.target.isContentEditable)) { if (e.key === "Escape") e.target.blur(); return; }
    var k = e.key;
    if (k === "ArrowRight" || k === " " || k === "PageDown" || k === "Enter") { e.preventDefault(); next(); }
    else if (k === "ArrowLeft" || k === "PageUp" || k === "Backspace") { e.preventDefault(); prev(); }
    else if (k === "Home") show(0, 0);
    else if (k === "End") show(slides.length - 1, 0);
    else if (k === "a" || k === "A") attack();
    else if (k === "n" || k === "N") notesEl.classList.toggle("show");
    else if (k === "g" || k === "G") overview.classList.toggle("show");
    else if (k === "t" || k === "T") { started = null; clearInterval(tick); renderNotes(); }
    else if (k === "p" || k === "P") exportPdf();
    else if (k === "f" || k === "F") toggleFull();
    else if (k === "Escape") { overview.classList.remove("show"); notesEl.classList.remove("show"); }
  });
  // ---- PDF export: every slide on its own 1280x720 page, every step shown, its own copy of the rail
  var printed = [];
  function prepPrint() {
    cleanPrint();
    slides.forEach(function (s) {
      applySteps(s, maxStep(s));
      if (s.hasAttribute("data-rail")) {
        s.classList.add("has-rail");
        var c = rail.cloneNode(true);
        c.id = ""; c.className = "railx rail-print";
        c.querySelector(".tokx").removeAttribute("id"); c.querySelector(".fill").removeAttribute("id");
        s.insertBefore(c, s.firstChild);
        setRailOn(c, s);
        printed.push(c);
      }
      Array.prototype.forEach.call(s.querySelectorAll(".attackbox"), function (a) { a.classList.add("run"); });
    });
  }
  function cleanPrint() {
    printed.forEach(function (c) { if (c.parentNode) c.parentNode.removeChild(c); });
    printed = [];
  }
  window.addEventListener("beforeprint", prepPrint);
  window.addEventListener("afterprint", function () { cleanPrint(); show(cur, step); });
  function exportPdf() {
    // In the print dialog choose "Save as PDF", paper size = the page size set by the deck, margins None, background graphics ON.
    prepPrint();
    setTimeout(function () { window.print(); }, 150);
  }
  document.getElementById("btnPdf").addEventListener("click", exportPdf);

  // ---- full screen: F key
  function toggleFull() {
    var el = document.documentElement;
    if (document.fullscreenElement) document.exitFullscreen(); else if (el.requestFullscreen) el.requestFullscreen();
  }

  // ---- team names: typed on slide 18, remembered in this browser only
  Array.prototype.forEach.call(document.querySelectorAll("input.name"), function (inp) {
    var key = "pf-demo-name-" + inp.getAttribute("data-key");
    try { var v = localStorage.getItem(key); if (v) inp.value = v; } catch (e) { /* storage may be blocked: the field still works */ }
    inp.addEventListener("input", function () { try { localStorage.setItem(key, inp.value); } catch (e) { /* ignore */ } });
    inp.addEventListener("keydown", function (e) { e.stopPropagation(); });
  });

  document.getElementById("btnNext").addEventListener("click", next);
  document.getElementById("btnPrev").addEventListener("click", prev);
  document.getElementById("btnNotes").addEventListener("click", function () { notesEl.classList.toggle("show"); });
  document.getElementById("btnGrid").addEventListener("click", function () { overview.classList.toggle("show"); });
  Array.prototype.forEach.call(document.querySelectorAll(".attackbtn"), function (b) { b.addEventListener("click", attack); });

  fit(); buildOverview();
  var start = parseInt((location.hash || "#1").slice(1), 10) || 1;
  var params = new URLSearchParams(location.search);
  if (params.get("notes")) notesEl.classList.add("show");
  if (params.get("static")) deck.classList.add("static");
  if (params.get("print")) { prepPrint(); }
  show(start - 1, parseInt(params.get("step") || "0", 10));
})();

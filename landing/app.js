"use strict";
const intro = document.getElementById('intro');
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
if (location.pathname === '/') {
  intro.hidden = false;
  const surface = [document.querySelector('.site-header'), document.querySelector('main'), document.querySelector('footer')];
  surface.forEach(el => el.inert = true);
  document.body.classList.add('intro-active');
  let finished = false;
  let frame;
  const finish = () => {
    if (finished) return;
    finished = true;
    cancelAnimationFrame(frame);
    intro.classList.add('leaving');
    setTimeout(() => {
      intro.hidden = true;
      surface.forEach(el => el.inert = false);
      document.body.classList.remove('intro-active');
    }, reduce ? 0 : 800);
  };
  document.getElementById('intro-skip').onclick = finish;
  const count = document.getElementById('intro-count');
  const bar = document.getElementById('intro-bar');
  const step = document.getElementById('intro-step');
  const started = performance.now();
  const duration = 5800;
  let phase = -1;
  const tick = now => {
    if (finished) return;
    const t = Math.min(1, (now - started) / duration);
    const n = Math.floor(100 * (t * t * (3 - 2 * t)));
    count.textContent = n;
    bar.style.transform = `scaleX(${n / 100})`;
    const next = t < .35 ? 0 : t < .75 ? 1 : t < 1 ? 2 : 3;
    if (next !== phase) {
      phase = next;
      step.textContent = ['Entering AEGIS', 'Discover your workspaces', 'Evidence starts here', 'Welcome to AEGIS'][next];
    }
    if (t < 1) frame = requestAnimationFrame(tick);
    else setTimeout(finish, 200);
  };
  frame = requestAnimationFrame(tick);
  // Intro progress is a visual sequence, independent of security analysis.
}

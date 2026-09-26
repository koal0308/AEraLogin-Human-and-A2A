/* Shared behaviour for AEra documentation pages: copy buttons, sidebar
   active-section highlighting, subtle background particles (as on landing). */
(function () {
    'use strict';

    function copyButtons() {
        document.querySelectorAll('.code-block').forEach(function (block) {
            var btn = block.querySelector('.copy-btn');
            var pre = block.querySelector('pre');
            if (!btn || !pre || !navigator.clipboard) { if (btn) btn.hidden = true; return; }
            btn.addEventListener('click', function () {
                navigator.clipboard.writeText(pre.textContent).then(function () {
                    btn.textContent = 'Copied!';
                    setTimeout(function () { btn.textContent = 'Copy'; }, 1800);
                });
            });
        });
    }

    function sidebarTracking() {
        var links = document.querySelectorAll('.doc-sidebar a[href^="#"]');
        if (!links.length || !('IntersectionObserver' in window)) return;
        var byId = {};
        links.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
        var obs = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (!e.isIntersecting) return;
                links.forEach(function (a) { a.classList.remove('active'); });
                var a = byId[e.target.id];
                if (a) a.classList.add('active');
            });
        }, { rootMargin: '-20% 0px -75% 0px' });
        Object.keys(byId).forEach(function (id) {
            var el = document.getElementById(id);
            if (el) obs.observe(el);
        });
    }

    function particles() {
        var holder = document.getElementById('bgCanvas');
        if (!holder || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        holder.appendChild(canvas);
        function size() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
        size();
        window.addEventListener('resize', size);
        var ps = [];
        for (var i = 0; i < 40; i++) {
            ps.push({ x: Math.random() * canvas.width, y: Math.random() * canvas.height,
                      vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5,
                      r: Math.random() * 2 + 1 });
        }
        (function frame() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ps.forEach(function (p) {
                p.x += p.vx; p.y += p.vy;
                if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
                ctx.fillStyle = 'rgba(0, 212, 255, 0.5)';
                ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
            });
            for (var a = 0; a < ps.length; a++) {
                for (var b = a + 1; b < ps.length; b++) {
                    var dx = ps[a].x - ps[b].x, dy = ps[a].y - ps[b].y;
                    var d = Math.sqrt(dx * dx + dy * dy);
                    if (d < 150) {
                        ctx.strokeStyle = 'rgba(0, 212, 255, ' + (0.2 * (1 - d / 150)) + ')';
                        ctx.lineWidth = 1;
                        ctx.beginPath(); ctx.moveTo(ps[a].x, ps[a].y); ctx.lineTo(ps[b].x, ps[b].y); ctx.stroke();
                    }
                }
            }
            requestAnimationFrame(frame);
        })();
    }

    function init() { copyButtons(); sidebarTracking(); particles(); }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();

/* AEra global site shell behaviour: mobile menu, dropdowns, current-page marking.
   Vanilla JS, no dependencies. Safe to load on any page that contains the shell. */
(function () {
    'use strict';

    function init() {
        var toggle = document.getElementById('siteMenuToggle');
        var menu = document.getElementById('siteMobileMenu');
        var backdrop = document.getElementById('siteMenuBackdrop');

        function setOpen(open) {
            if (!toggle || !menu || !backdrop) return;
            menu.classList.toggle('active', open);
            backdrop.classList.toggle('active', open);
            toggle.textContent = open ? '\u2715' : '\u2630';
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }

        if (toggle && menu && backdrop) {
            toggle.addEventListener('click', function () {
                setOpen(!menu.classList.contains('active'));
            });
            backdrop.addEventListener('click', function () { setOpen(false); });
            menu.querySelectorAll('a').forEach(function (a) {
                a.addEventListener('click', function () { setOpen(false); });
            });
        }

        // Desktop dropdowns: click/keyboard support in addition to CSS hover.
        var dropdowns = document.querySelectorAll('.site-dropdown');
        dropdowns.forEach(function (dd) {
            var btn = dd.querySelector('.site-dropdown-toggle');
            if (!btn) return;
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var open = !dd.classList.contains('open');
                dropdowns.forEach(function (o) {
                    o.classList.remove('open');
                    var b = o.querySelector('.site-dropdown-toggle');
                    if (b) b.setAttribute('aria-expanded', 'false');
                });
                dd.classList.toggle('open', open);
                btn.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        });
        document.addEventListener('click', function () {
            dropdowns.forEach(function (o) {
                o.classList.remove('open');
                var b = o.querySelector('.site-dropdown-toggle');
                if (b) b.setAttribute('aria-expanded', 'false');
            });
        });

        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            setOpen(false);
            dropdowns.forEach(function (o) { o.classList.remove('open'); });
        });

        // Mark the current page in header + mobile menu.
        var path = window.location.pathname.replace(/\/+$/, '') || '/';
        var aliases = { '/docs/sdk-documentation.html': '/sdk-docs', '/landing': '/' };
        path = aliases[path] || path;
        document.querySelectorAll('.site-nav a, .site-mobile-menu a').forEach(function (a) {
            var href = a.getAttribute('href') || '';
            if (href.indexOf('#') !== -1 || /^https?:/.test(href)) return;
            if (href.replace(/\/+$/, '') === path) {
                a.setAttribute('aria-current', 'page');
                var dd = a.closest('.site-dropdown');
                if (dd) {
                    var b = dd.querySelector('.site-dropdown-toggle');
                    if (b) b.classList.add('is-current');
                }
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

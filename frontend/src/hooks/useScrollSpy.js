import { useEffect, useState } from "react";

/**
 * Tracks which of several real page sections (each a DOM id already
 * rendered in App.jsx) is currently in view, so the sidebar's workflow nav
 * can highlight the section the analyst is actually looking at — a real
 * IntersectionObserver-backed scrollspy, not a static list of buttons that
 * don't reflect anything.
 */
export function useScrollSpy(sectionIds) {
  const [activeId, setActiveId] = useState(sectionIds[0] || null);

  useEffect(() => {
    const elements = sectionIds.map((id) => document.getElementById(id)).filter(Boolean);
    if (elements.length === 0) return undefined;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length === 0) return;
        // Whichever visible section's top edge is closest to the top of
        // the viewport — more stable while scrolling than "most area
        // intersecting", which flickers between adjacent short sections.
        const top = visible.reduce((best, e) =>
          e.boundingClientRect.top < best.boundingClientRect.top ? e : best
        );
        setActiveId(top.target.id);
      },
      { rootMargin: "-10% 0px -75% 0px", threshold: [0, 1] }
    );

    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
    // sectionIds is a small static array defined at module scope by the
    // caller — join() gives a stable dependency without re-observing on
    // every render from a fresh array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sectionIds.join(",")]);

  return activeId;
}

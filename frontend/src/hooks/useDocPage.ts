import { useState, useEffect, useCallback, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

export interface DocSectionMeta {
  id: string;
  title: string;
  icon?: string;
  group?: string; // optional TOC grouping (e.g. category on Methods)
}

/**
 * Shared documentation-page chassis: sticky-TOC navigation state,
 * scroll-spy, and hash deep-linking. Used by Help and Methods.
 *
 * Mechanics ported from Delta's Help (numbers encode real tuning):
 * - IntersectionObserver rootMargin '-80px 0px -60% 0px' — top 80px is
 *   dead (sticky-header clearance); a section becomes active once it
 *   crosses into the top 40% of the viewport.
 * - Section ids are namespaced `doc-section-${id}`; the observer strips
 *   the prefix.
 * - Hash deep links (/help#faq) set active on mount and on hash change;
 *   TOC clicks navigate with {replace: true} so URLs share and the back
 *   button behaves.
 */
export function useDocPage(basePath: string, sections: DocSectionMeta[]) {
  const [activeSection, setActiveSection] = useState(sections[0]?.id ?? '');
  const navigating = useRef(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Deep link: on mount and on hash change
  useEffect(() => {
    const hash = location.hash.replace('#', '');
    if (hash && sections.some((s) => s.id === hash)) {
      setActiveSection(hash);
      const el = document.getElementById(`doc-section-${hash}`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [location.hash, sections]);

  // Scroll-spy
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting && !navigating.current) {
            const id = entry.target.id.replace('doc-section-', '');
            setActiveSection(id);
          }
        }
      },
      { rootMargin: '-80px 0px -60% 0px' }
    );

    for (const s of sections) {
      const el = document.getElementById(`doc-section-${s.id}`);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [sections]);

  // TOC click: navigate (URL shares) + smooth scroll
  const goToSection = useCallback(
    (id: string) => {
      setActiveSection(id);
      navigating.current = true;
      navigate(`${basePath}#${id}`, { replace: true });
      const el = document.getElementById(`doc-section-${id}`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Re-enable scroll-spy after the smooth scroll settles
      window.setTimeout(() => {
        navigating.current = false;
      }, 700);
    },
    [basePath, navigate]
  );

  return { activeSection, goToSection };
}

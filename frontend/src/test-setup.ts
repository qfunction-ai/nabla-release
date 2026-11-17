import '@testing-library/jest-dom/vitest';

// jsdom does not implement scrollIntoView; doc pages call it on TOC
// navigation and hash deep links. Stub it or every Help/Methods test throws.
Element.prototype.scrollIntoView = () => {};

// jsdom does not implement IntersectionObserver; the shared doc-page
// chassis uses it for scroll-spy. Stub with a no-op observer.
class IntersectionObserverStub {
  readonly root: Element | null = null;
  readonly rootMargin: string = '';
  readonly thresholds: ReadonlyArray<number> = [];
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}
globalThis.IntersectionObserver = IntersectionObserverStub as unknown as typeof IntersectionObserver;

/**
 * Local-scoped scan storage with abstraction layer.
 * Uses localStorage so data persists across tab closes and browser restarts.
 */

const STORAGE_KEY = "risk_analyzer_scans";

function _getStore() {
  if (typeof window === "undefined") return [];
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function _setStore(data) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // Storage full or unavailable
  }
}

export const scanStore = {
  save(scanResult) {
    const scans = _getStore();
    scans.push({
      ...scanResult,
      timestamp: new Date().toISOString(),
      id: Date.now().toString(),
    });
    _setStore(scans);
    return scans;
  },

  getAll() {
    return _getStore();
  },

  getById(id) {
    const scans = _getStore();
    return scans.find((s) => s.id === id) || null;
  },

  deleteById(id) {
    const scans = _getStore().filter((s) => s.id !== id);
    _setStore(scans);
    return scans;
  },

  getStats() {
    const scans = _getStore();
    if (scans.length === 0) {
      return {
        totalScans: 0,
        averageScore: 0,
        distribution: { safe: 0, suspicious: 0, dangerous: 0 },
        indicatorFrequency: {},
        byType: { url: 0, email: 0 },
      };
    }

    const totalScans = scans.length;
    const averageScore = Math.round(
      scans.reduce((sum, s) => sum + s.overall_score, 0) / totalScans
    );

    const distribution = { safe: 0, suspicious: 0, dangerous: 0 };
    const indicatorFrequency = {};
    const byType = { url: 0, email: 0 };

    scans.forEach((scan) => {
      distribution[scan.label] = (distribution[scan.label] || 0) + 1;
      byType[scan.scan_type] = (byType[scan.scan_type] || 0) + 1;

      (scan.indicators || []).forEach((ind) => {
        indicatorFrequency[ind.name] = (indicatorFrequency[ind.name] || 0) + 1;
      });
    });

    return { totalScans, averageScore, distribution, indicatorFrequency, byType };
  },

  clear() {
    if (typeof window === "undefined") return;
    localStorage.removeItem(STORAGE_KEY);
  },
};

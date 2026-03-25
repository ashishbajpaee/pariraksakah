import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Feature, FeatureCollection, Geometry } from 'geojson';

// ── Threat arc data (lon/lat coordinates) ──────

interface ThreatArc {
  from: [number, number]; // [longitude, latitude]
  to: [number, number];
  severity: 'critical' | 'high' | 'medium';
  label: string;
}

const THREAT_ARCS: ThreatArc[] = [
  { from: [-77.0, 38.9],   to: [2.3, 48.9],    severity: 'critical', label: 'US → France (APT29)' },
  { from: [116.4, 39.9],   to: [-77.0, 38.9],  severity: 'critical', label: 'China → US (C2)' },
  { from: [37.6, 55.8],    to: [2.3, 48.9],    severity: 'high',     label: 'Russia → Europe' },
  { from: [103.8, 1.4],    to: [151.2, -33.9], severity: 'medium',   label: 'SEA → Australia' },
  { from: [28.0, -26.2],   to: [2.3, 48.9],    severity: 'high',     label: 'S.Africa → Europe' },
  { from: [116.4, 39.9],   to: [139.7, 35.7],  severity: 'critical', label: 'China → Japan' },
  { from: [-46.6, -23.5],  to: [-77.0, 38.9],  severity: 'medium',   label: 'Brazil → US' },
  { from: [51.4, 35.7],    to: [2.3, 48.9],    severity: 'high',     label: 'Iran → Europe' },
];

// Hotspot cities [lon, lat]
const HOTSPOTS: { coords: [number, number]; severity: string; city: string }[] = [
  { coords: [-77.0, 38.9],  severity: 'critical', city: 'Washington DC' },
  { coords: [116.4, 39.9],  severity: 'high',     city: 'Beijing' },
  { coords: [37.6, 55.8],   severity: 'high',     city: 'Moscow' },
  { coords: [2.3, 48.9],    severity: 'medium',   city: 'Paris' },
  { coords: [139.7, 35.7],  severity: 'high',     city: 'Tokyo' },
  { coords: [28.0, -26.2],  severity: 'medium',   city: 'Johannesburg' },
  { coords: [-43.2, -22.9], severity: 'medium',   city: 'São Paulo' },
  { coords: [55.3, 25.2],   severity: 'medium',   city: 'Dubai' },
];

const ARC_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#F59E0B',
};

const W = 800;
const H = 380;

// ── Component ──────────────────────────────────

export default function ThreatGlobe() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null);
  const [geoReady, setGeoReady] = useState(false);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // ── Projection ─────────────────────────────
    const projection = d3.geoNaturalEarth1()
      .scale(140)
      .translate([W / 2, H / 2 + 20]);

    const pathGen = d3.geoPath().projection(projection);

    // ── Background ─────────────────────────────
    svg.append('rect')
      .attr('width', W)
      .attr('height', H)
      .attr('fill', '#F3F7FF')
      .attr('rx', 10);

    // ── Graticule grid ──────────────────────────
    const graticule = d3.geoGraticule().step([20, 20]);
    svg.append('path')
      .datum(graticule())
      .attr('d', pathGen)
      .attr('fill', 'none')
      .attr('stroke', '#D7E3F8')
      .attr('stroke-width', 0.4)
      .attr('opacity', 0.8);

    // ── Sphere outline ──────────────────────────
    svg.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('d', pathGen)
      .attr('fill', 'none')
      .attr('stroke', '#BFD1EE')
      .attr('stroke-width', 0.8);

    // ── Load + render GeoJSON ───────────────────
    d3.json<FeatureCollection>('/world.geo.json').then((world) => {
      if (!world) return;

      const countriesGroup = svg.append('g').attr('class', 'countries');

      countriesGroup.selectAll<SVGPathElement, Feature<Geometry>>('path')
        .data(world.features)
        .join('path')
        .attr('d', (f) => pathGen(f) || '')
        .attr('fill', '#DCE8FF')
        .attr('stroke', '#517EF9')
        .attr('stroke-width', 0.3)
        .attr('opacity', 0.85)
        .on('mouseenter', function (event, d) {
          d3.select(this).attr('fill', '#517EF9').attr('opacity', 1);
          const name = (d.properties as any)?.name || (d.properties as any)?.admin || '';
          if (name) setTooltip({ x: event.offsetX, y: event.offsetY, text: name });
        })
        .on('mousemove', function (event) {
          setTooltip((t) => t ? { ...t, x: event.offsetX, y: event.offsetY } : null);
        })
        .on('mouseleave', function () {
          d3.select(this).attr('fill', '#DCE8FF').attr('opacity', 0.85);
          setTooltip(null);
        });

      setGeoReady(true);

      // ── Threat arcs ─────────────────────────
      const arcsGroup = svg.append('g').attr('class', 'arcs');

      THREAT_ARCS.forEach((arc, i) => {
        const src = projection(arc.from);
        const tgt = projection(arc.to);
        if (!src || !tgt) return;

        const [sx, sy] = src;
        const [tx, ty] = tgt;
        const mx = (sx + tx) / 2;
        const my = Math.min(sy, ty) - 55 - i * 5;

        const totalLen = Math.sqrt((tx - sx) ** 2 + (ty - sy) ** 2) * 2;
        const color = ARC_COLORS[arc.severity];

        const path = arcsGroup.append('path')
          .attr('d', `M${sx},${sy} Q${mx},${my} ${tx},${ty}`)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', arc.severity === 'critical' ? 1.8 : 1.2)
          .attr('opacity', 0.7)
          .attr('stroke-dasharray', totalLen)
          .attr('stroke-dashoffset', totalLen);

        // Animate arc draw repeatedly
        function animateArc() {
          path
            .attr('stroke-dashoffset', totalLen)
            .transition()
            .duration(1800)
            .delay(i * 400)
            .ease(d3.easeLinear)
            .attr('stroke-dashoffset', 0)
            .on('end', () => {
              setTimeout(animateArc, 2000 + i * 300);
            });
        }
        animateArc();

        // Source pulsing dot
        arcsGroup.append('circle')
          .attr('cx', sx).attr('cy', sy).attr('r', 3)
          .attr('fill', color)
          .call((c) => {
            function pulse() {
              c.transition().duration(800).attr('opacity', 0.3)
               .transition().duration(800).attr('opacity', 1)
               .on('end', pulse);
            }
            pulse();
          });

        // Target dot
        arcsGroup.append('circle')
          .attr('cx', tx).attr('cy', ty).attr('r', 2.5)
          .attr('fill', color)
          .attr('opacity', 0.8);
      });

      // ── Hotspot pulses ───────────────────────
      const hotGroup = svg.append('g').attr('class', 'hotspots');

      HOTSPOTS.forEach((h, i) => {
        const pos = projection(h.coords);
        if (!pos) return;
        const [cx, cy] = pos;
        const color = ARC_COLORS[h.severity] || '#517EF9';

        // Outer pulse ring
        const ring = hotGroup.append('circle')
          .attr('cx', cx).attr('cy', cy)
          .attr('r', 5)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', 1)
          .attr('opacity', 0.8);

        function pulseRing() {
          ring
            .attr('r', 5).attr('opacity', 0.8)
            .transition().duration(1400).delay(i * 200)
            .ease(d3.easeLinear)
            .attr('r', 18).attr('opacity', 0)
            .on('end', pulseRing);
        }
        pulseRing();

        // Inner solid dot
        hotGroup.append('circle')
          .attr('cx', cx).attr('cy', cy).attr('r', 3)
          .attr('fill', color)
          .attr('opacity', 0.9);
      });
    }).catch(() => {
      // Fallback if GeoJSON fails to load — show message
      svg.append('text')
        .attr('x', W / 2).attr('y', H / 2)
        .attr('text-anchor', 'middle')
        .attr('fill', '#5f6f8a')
        .attr('font-size', 14)
        .text('Map loading...');
    });
  }, []);

  return (
    <div className="relative w-full">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        className="rounded-lg"
      />
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-white text-slate-700 text-xs px-2 py-1 rounded border border-[#D8E3F7] shadow-lg"
          style={{ left: tooltip.x + 12, top: tooltip.y - 10 }}
        >
          {tooltip.text}
        </div>
      )}
      {/* Legend */}
      <div className="flex gap-4 mt-2 text-xs text-slate-500 justify-end">
        {Object.entries(ARC_COLORS).map(([sev, color]) => (
          <span key={sev} className="flex items-center gap-1">
            <span className="w-3 h-0.5 inline-block rounded" style={{ background: color }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  );
}

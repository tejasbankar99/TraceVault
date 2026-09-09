import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet'
import L from 'leaflet'
import { cn } from '@/lib/utils'
import type { GeoIntelligence } from '@/types'

// Fix leaflet icon issue with webpack/vite
delete (L.Icon.Default.prototype as unknown as { _getIconUrl: unknown })._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
})

function createColoredMarker(color: string) {
  return new L.Icon({
    iconUrl: `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 36'%3E%3Cpath d='M12 0C5.37 0 0 5.37 0 12c0 9 12 24 12 24S24 21 24 12C24 5.37 18.63 0 12 0z' fill='${encodeURIComponent(color)}'/%3E%3Ccircle cx='12' cy='12' r='4' fill='white'/%3E%3C/svg%3E`,
    iconSize: [24, 36],
    iconAnchor: [12, 36],
    popupAnchor: [0, -36],
  })
}

const TOR_ICON = createColoredMarker('#dc2626')
const VPN_ICON = createColoredMarker('#ea580c')
const CLOUD_ICON = createColoredMarker('#38bdf8')
const HOSTING_ICON = createColoredMarker('#818cf8')
const NORMAL_ICON = createColoredMarker('#6366f1')

function getInfrastructureInfo(geo: GeoIntelligence) {
  if (geo.is_tor) return { label: 'TOR Exit Node', color: 'bg-red-600', icon: TOR_ICON }
  if (geo.is_vpn) return { label: 'VPN Node', color: 'bg-orange-600', icon: VPN_ICON }
  
  const org = ((geo.isp || '') + ' ' + (geo.org || '')).toLowerCase()
  if (org.includes('google') || org.includes('microsoft') || org.includes('amazon') || org.includes('cloudflare')) {
    return { label: 'Enterprise Cloud MTA', color: 'bg-sky-500', icon: CLOUD_ICON }
  }
  if (geo.is_hosting) return { label: 'Data Center / Hosting', color: 'bg-indigo-500', icon: HOSTING_ICON }
  return { label: 'Relay Server', color: 'bg-primary', icon: NORMAL_ICON }
}

interface GeoIntelMapProps {
  geoData: GeoIntelligence[]
}

export default function GeoIntelMap({ geoData }: GeoIntelMapProps) {
  // Find valid coordinates
  const withCoords = geoData.filter(g => g.latitude !== null && g.longitude !== null)
  const center: [number, number] = withCoords.length > 0
    ? [withCoords[0].latitude!, withCoords[0].longitude!]
    : [20, 0]

  // Flight path positions for polyline
  const routePositions: [number, number][] = withCoords.map(g => [g.latitude!, g.longitude!])

  return (
    <div className="space-y-3">
      <div className="rounded-xl overflow-hidden border border-border relative" style={{ height: '340px' }}>
        <MapContainer
          center={center}
          zoom={withCoords.length > 0 ? 4 : 2}
          style={{ height: '100%', width: '100%', background: '#0f172a' }}
          attributionControl={false}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            className="osm-dark-filter"
          />

          {/* Connect multi-hop relays with route line */}
          {routePositions.length > 1 && (
            <Polyline
              positions={routePositions}
              pathOptions={{
                color: '#6366f1',
                weight: 3,
                dashArray: '6, 8',
                opacity: 0.8,
              }}
            />
          )}

          {geoData.map((geo, idx) => {
            if (!geo.latitude || !geo.longitude) return null
            const infra = getInfrastructureInfo(geo)
            return (
              <Marker
                key={geo.id || idx}
                position={[geo.latitude, geo.longitude]}
                icon={infra.icon}
              >
                <Popup className="leaflet-popup-dark">
                  <div className="min-w-56 text-sm p-1">
                    <div className="flex items-center justify-between mb-1.5">
                      <p className="font-mono font-bold text-base text-foreground">{geo.ip_address}</p>
                      <span className={cn('text-[10px] font-semibold px-2 py-0.5 rounded text-white', infra.color)}>
                        {infra.label}
                      </span>
                    </div>
                    <div className="space-y-1 text-gray-300 text-xs">
                      <p>📍 {[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}</p>
                      {geo.isp && <p>🏢 {geo.isp}</p>}
                      {geo.asn && <p>📡 ASN: {geo.asn}</p>}
                    </div>

                    {infra.label === 'Enterprise Cloud MTA' && (
                      <p className="mt-2 text-[10px] text-sky-300 bg-sky-950/60 border border-sky-800/60 p-1.5 rounded leading-tight">
                        Transmitting Cloud MTA. Personal residential client IPs are sanitized by webmail providers for privacy.
                      </p>
                    )}
                  </div>
                </Popup>
              </Marker>
            )
          })}
        </MapContainer>
      </div>

      {/* Enhanced Legend */}
      <div className="flex items-center justify-between flex-wrap gap-2 text-xs text-muted-foreground px-1">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="font-medium text-foreground">Infrastructure Types:</span>
          {[
            { color: 'bg-sky-500', label: 'Cloud MTA (Google/MS)' },
            { color: 'bg-indigo-500', label: 'Hosting / VPS' },
            { color: 'bg-orange-600', label: 'VPN Node' },
            { color: 'bg-red-600', label: 'TOR Exit' },
            { color: 'bg-primary', label: 'Standard Relay' },
          ].map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className={cn('w-2.5 h-2.5 rounded-full', color)} />
              {label}
            </span>
          ))}
        </div>
        {routePositions.length > 1 && (
          <span className="text-[11px] text-indigo-400 font-mono">
            — - — Relay Flight Route ({routePositions.length} hops)
          </span>
        )}
      </div>
    </div>
  )
}


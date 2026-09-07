import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
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
const HOSTING_ICON = createColoredMarker('#2563eb')
const NORMAL_ICON = createColoredMarker('#6366f1')

function getIcon(geo: GeoIntelligence) {
  if (geo.is_tor)     return TOR_ICON
  if (geo.is_vpn)     return VPN_ICON
  if (geo.is_hosting) return HOSTING_ICON
  return NORMAL_ICON
}

interface GeoIntelMapProps {
  geoData: GeoIntelligence[]
}

export default function GeoIntelMap({ geoData }: GeoIntelMapProps) {
  // Find first valid coordinate to center map
  const withCoords = geoData.filter(g => g.latitude !== null && g.longitude !== null)
  const center: [number, number] = withCoords.length > 0
    ? [withCoords[0].latitude!, withCoords[0].longitude!]
    : [20, 0]

  return (
    <div className="space-y-3">
      <div className="rounded-xl overflow-hidden border border-border" style={{ height: '320px' }}>
        <MapContainer
          center={center}
          zoom={withCoords.length > 0 ? 4 : 2}
          style={{ height: '100%', width: '100%', background: '#0f172a' }}
          attributionControl={false}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
          />
          {geoData.map(geo => {
            if (!geo.latitude || !geo.longitude) return null
            return (
              <Marker
                key={geo.id}
                position={[geo.latitude, geo.longitude]}
                icon={getIcon(geo)}
              >
                <Popup className="leaflet-popup-dark">
                  <div className="min-w-52 text-sm">
                    <p className="font-mono font-bold text-base mb-2">{geo.ip_address}</p>
                    <div className="space-y-1 text-gray-300">
                      <p>📍 {[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}</p>
                      {geo.isp && <p>🌐 {geo.isp}</p>}
                      {geo.asn && <p>📡 ASN: {geo.asn}</p>}
                    </div>
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {geo.is_tor     && <span className="text-xs px-1.5 py-0.5 rounded bg-red-700 text-white">TOR</span>}
                      {geo.is_vpn     && <span className="text-xs px-1.5 py-0.5 rounded bg-orange-700 text-white">VPN</span>}
                      {geo.is_hosting && <span className="text-xs px-1.5 py-0.5 rounded bg-blue-700 text-white">HOSTING</span>}
                      {geo.is_proxy   && <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-700 text-white">PROXY</span>}
                    </div>
                  </div>
                </Popup>
              </Marker>
            )
          })}
        </MapContainer>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="font-medium">Markers:</span>
        {[
          { color: 'bg-red-600', label: 'TOR Exit' },
          { color: 'bg-orange-600', label: 'VPN' },
          { color: 'bg-blue-600', label: 'Hosting' },
          { color: 'bg-primary', label: 'Regular' },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5">
            <span className={cn('w-2.5 h-2.5 rounded-full', color)} />
            {label}
          </span>
        ))}
      </div>
    </div>
  )
}

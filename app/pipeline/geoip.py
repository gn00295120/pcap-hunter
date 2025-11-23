from __future__ import annotations

from typing import Any, Dict, Optional

from geolite2 import geolite2


class GeoIP:
    _reader = None

    @classmethod
    def get_reader(cls):
        if cls._reader is None:
            cls._reader = geolite2.reader()
        return cls._reader

    @classmethod
    def lookup(cls, ip: str) -> Optional[Dict[str, Any]]:
        try:
            reader = cls.get_reader()
            match = reader.get(ip)
            if not match:
                return None

            country = match.get("country", {}).get("names", {}).get("en", "Unknown")
            city = match.get("city", {}).get("names", {}).get("en", "Unknown")
            loc = match.get("location", {})
            lat = loc.get("latitude")
            lon = loc.get("longitude")

            if lat is None or lon is None:
                return None

            return {"ip": ip, "country": country, "city": city, "lat": lat, "lon": lon}
        except Exception:
            return None

    @classmethod
    def close(cls):
        if cls._reader:
            geolite2.close()
            cls._reader = None

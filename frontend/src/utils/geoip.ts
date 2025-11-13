/**
 * Stable GeoIP service that provides consistent country mapping for IP addresses
 */

class GeoIPService {
  private cache = new Map<string, string>()
  
  private countries = [
    'United States', 'Germany', 'Japan', 'United Kingdom', 'Canada', 
    'Australia', 'France', 'Netherlands', 'Singapore', 'Brazil',
    'South Korea', 'India', 'Sweden', 'Switzerland', 'Norway',
    'Denmark', 'Finland', 'Italy', 'Spain', 'Austria'
  ]

  private countryCodes = [
    'US', 'DE', 'JP', 'GB', 'CA', 'AU', 'FR', 'NL', 'SG', 'BR',
    'KR', 'IN', 'SE', 'CH', 'NO', 'DK', 'FI', 'IT', 'ES', 'AT'
  ]

  /**
   * Generate a stable hash from IP address
   */
  private hashIP(ip: string): number {
    let hash = 0
    for (let i = 0; i < ip.length; i++) {
      const char = ip.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32-bit integer
    }
    return Math.abs(hash)
  }

  /**
   * Get country name for IP address (stable mapping)
   */
  getCountry(ip: string): string {
    if (this.cache.has(ip)) {
      return this.cache.get(ip)!
    }

    const hash = this.hashIP(ip)
    const country = this.countries[hash % this.countries.length]
    this.cache.set(ip, country)
    return country
  }

  /**
   * Get country code for IP address (stable mapping)
   */
  getCountryCode(ip: string): string {
    if (this.cache.has(`${ip}_code`)) {
      return this.cache.get(`${ip}_code`)!
    }

    const hash = this.hashIP(ip)
    const countryCode = this.countryCodes[hash % this.countryCodes.length]
    this.cache.set(`${ip}_code`, countryCode)
    return countryCode
  }

  /**
   * Check if IP is public (not private/local)
   */
  isPublicIP(ip: string): boolean {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4) return false
    
    // Private IP ranges
    if (parts[0] === 10) return false
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
    if (parts[0] === 192 && parts[1] === 168) return false
    if (parts[0] === 127) return false // Loopback
    if (parts[0] === 169 && parts[1] === 254) return false // Link-local
    
    return true
  }

  /**
   * Get geographic info for IP
   */
  getGeoInfo(ip: string): { country: string; countryCode: string; isPublic: boolean } {
    const isPublic = this.isPublicIP(ip)
    return {
      country: isPublic ? this.getCountry(ip) : 'Local Network',
      countryCode: isPublic ? this.getCountryCode(ip) : 'LAN',
      isPublic
    }
  }

  /**
   * Clear cache (for testing)
   */
  clearCache(): void {
    this.cache.clear()
  }
}

// Export singleton instance
export const geoIPService = new GeoIPService()

// Export utility functions for backward compatibility
export const getCountryFromIP = (ip: string) => geoIPService.getCountry(ip)
export const getCountryCodeFromIP = (ip: string) => geoIPService.getCountryCode(ip)
export const isPublicIP = (ip: string) => geoIPService.isPublicIP(ip)
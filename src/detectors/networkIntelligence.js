/**
 * Network/IP Intelligence Detection Module
 *
 * This module provides client-side detection capabilities and
 * integrates with server-side IP intelligence services.
 *
 * Client-side capabilities:
 * - WebRTC IP leak detection
 * - Geolocation vs IP correlation
 * - Timezone consistency with IP
 * - Network connection quality analysis
 *
 * Server-side (integration module):
 * - Datacenter IP detection (ASN mapping)
 * - VPN/Proxy detection
 * - Residential vs datacenter classification
 * - IP velocity/impossibility detection
 */

import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';

/**
 * Detect WebRTC IP leaks that might indicate VPN/proxy
 */
function detectWebRTCIPIndicators() {
  const indicators = [];

  return new Promise((resolve) => {
    try {
      const peerConnection = new (window.RTCPeerConnection || window.webkitRTCPeerConnection)({
        iceServers: []
      });

      const foundIPs = new Set();
      let timeout;

      const onIceCandidate = (event) => {
        if (!event.candidate) return;

        const candidate = event.candidate.candidate;
        const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);

        if (ipMatch) {
          foundIPs.add(ipMatch[1]);

          // Local IP indicators
          if (/^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\./.test(ipMatch[1])) {
            indicators.push({
              type: 'local-ip',
              ip: ipMatch[1],
              category: 'expected'
            });
          }
          // Public IP (potential leak)
          else {
            indicators.push({
              type: 'public-ip',
              ip: ipMatch[1],
              category: 'possible-leak'
            });
          }
        }
      };

      peerConnection.onicecandidate = onIceCandidate;
      peerConnection.createDataChannel('webrtc-detection');
      peerConnection.createOffer().then(
        plan => peerConnection.setLocalDescription(plan),
        () => { }
      );

      timeout = setTimeout(() => {
        peerConnection.close();
        resolve({
          ipCount: foundIPs.size,
          indicators,
          detected: foundIPs.size > 0
        });
      }, 3000);
    } catch (err) {
      resolve({
        ipCount: 0,
        indicators: [],
        detected: false,
        error: String(err)
      });
    }
  });
}

/**
 * Analyze network quality as indicator of datacenter/residential
 */
function analyzeNetworkQuality() {
  const info = navigator.connection || navigator.mozConnection || navigator.webkitConnection;

  if (!info) {
    return {
      available: false,
      evidence: {}
    };
  }

  const effectiveness = info.effectiveType; // 'slow-2g', '2g', '3g', '4g'
  const rtt = info.rtt || 0; // Round-trip time in ms
  const downlink = info.downlink || 0; // Bandwidth in Mbps
  const saveData = info.saveData || false;

  const evidence = {
    effectiveType: effectiveness,
    rtt,
    downlink,
    saveData
  };

  // Suspicion indicators
  const suspicions = [];

  // Datacenter connections often have very low latency (< 1ms)
  if (rtt < 1) {
    suspicions.push({
      type: 'suspiciously-low-rtt',
      value: rtt,
      confidence: 0.58
    });
  }

  // Very high bandwidth (>500 Mbps) suggests datacenter
  if (downlink > 500) {
    suspicions.push({
      type: 'suspiciously-high-bandwidth',
      value: downlink,
      confidence: 0.55
    });
  }

  // 3G/slow-2g from "datacenter" IP is suspicious
  if ((effectiveness === '3g' || effectiveness === 'slow-2g') && rtt < 5) {
    suspicions.push({
      type: 'mismatched-connection-type',
      value: `${effectiveness} with RTT ${rtt}ms`,
      confidence: 0.60
    });
  }

  return {
    available: true,
    evidence,
    suspicions
  };
}

/**
 * Check geolocation vs timezone consistency
 * (requires geolocation API access)
 */
function checkGeoLocationConsistency() {
  const results = {
    checked: false,
    timezone: null,
    locale: null,
    geolocationChecks: []
  };

  try {
    // Get timezone from system
    const tzOffset = new Date().getTimezoneOffset();
    results.timezone = {
      offset: tzOffset,
      offsetHours: -tzOffset / 60
    };

    // Get locale
    results.locale = navigator.language || 'unknown';

    // Map timezone offset to likely regions
    const tzRegions = {
      0: ['UTC', 'UK', 'Portugal'],
      -60: ['Europe'],
      -120: ['Egypt', 'Eastern Africa'],
      -300: ['Eastern US'],
      -360: ['Central US'],
      -420: ['Mountain US'],
      -480: ['Pacific US', 'California']
    };

    results.geolocationChecks = tzRegions[Math.abs(tzOffset)] || [];

  } catch (err) {
    results.error = String(err);
  }

  return results;
}

/**
 * Detect VPN/Proxy indicators from network behavior
 */
function detectVPNProxyIndicators() {
  const indicators = [];

  try {
    // Check for DNS leak (would require external DNS query, skip for now)
    // Check for WebRTC leak is handled separately

    // Check network quality anomalies
    const netQuality = analyzeNetworkQuality();
    if (netQuality.suspicions.length > 0) {
      indicators.push({
        type: 'network-quality-anomaly',
        details: netQuality.suspicions
      });
    }

    // Check for common VPN/proxy patterns in header patterns
    // This would require server-side analysis

    // Check timezone vs browser detection
    const tzOffset = new Date().getTimezoneOffset();
    const tzHours = -tzOffset / 60;

    // Suspicious if timezone doesn't match typical values
    const validOffsets = [-12, -11, -10, -9.5, -9, -8, -7, -6, -5, -4, -3.5, -3, -2, -1, 0, 1, 2, 3, 3.5, 4, 4.5, 5, 5.5, 5.75, 6, 6.5, 7, 8, 8.45, 8.75, 9, 9.5, 10, 10.5, 11, 11.5, 12, 12.45, 12.75, 13, 14];

    if (!validOffsets.includes(tzHours)) {
      indicators.push({
        type: 'invalid-timezone-offset',
        value: tzHours,
        confidence: 0.65
      });
    }

  } catch (err) {
    // Ignore
  }

  return indicators;
}

/**
 * Analyze HTTP/2 characteristics (requires server-side support)
 * Client can provide information about connection capabilities
 */
function analyzeHTTPConnectionProfile() {
  const profile = {
    http2Supported: 'http2' in (navigator.connection || {}),
    http3Supported: /HTTP\/3/.test(navigator.appVersion || ''),
    timeToFirstByte: undefined,
    connectionLatency: undefined
  };

  // Measure time to first resource
  try {
    const resources = performance.getEntriesByType?.('resource') || [];
    if (resources.length > 0) {
      const timings = resources.map(r => r.responseStart - r.fetchStart);
      profile.timeToFirstByte = timings[0] || undefined;
    }
  } catch (e) {
    // Ignore
  }

  return profile;
}

/**
 * Generate IP-related signals
 */
function generateIPSignals(webrtcData, networkAnalysis, vpnIndicators) {
  const signals = [];

  // WebRTC public IP leak (might indicate VPN)
  if (webrtcData.indicators.some(i => i.category === 'possible-leak')) {
    signals.push(
      createDetectorResult({
        key: 'webrtcPublicIPLeak',
        label: 'WebRTC Public IP Leak',
        value: true,
        evidence: webrtcData.indicators,
        category: 'environment',
        severity: 'soft',
        weight: 4,
        confidence: 62,
        state: 'suspicious'
      })
    );
  }

  // VPN/Proxy indicators
  if (vpnIndicators.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'vpnProxyIndicators',
        label: 'VPN/Proxy Usage Indicators',
        value: true,
        evidence: vpnIndicators,
        category: 'environment',
        severity: 'soft',
        weight: 5,
        confidence: 55,
        state: 'suspicious'
      })
    );
  }

  return signals;
}

/**
 * Server-side IP intelligence integration module
 * This should be called on the server with the client IP
 */
export function createServerSideIPAnalyzer() {
  return {
    /**
     * Analyze IP against datacenter/VPN databases
     * Requires external API or local database
     */
    async analyzeIP(clientIP, apiKey = null) {
      const analysis = {
        ip: clientIP,
        classification: null, // 'residential', 'datacenter', 'vpn', 'proxy', 'unknown'
        provider: null,
        asn: null,
        riskScore: 0,
        indicators: []
      };

      // This is a placeholder - integrate with MaxMind, AbuseIPDB, etc.
      // Example integration:
      // const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${clientIP}`, {
      //   headers: { Key: apiKey }
      // });
      // const data = await response.json();
      // analysis.provider = data.data.provider;
      // analysis.riskScore = data.data.abuseConfidenceScore;

      return analysis;
    },

    /**
     * Detect datacenter IPs via ASN mapping
     */
    async detectDatacenterIP(clientIP) {
      const datacenters = [
        { range: '1.1.1.0/24', provider: 'cloudflare', type: 'dns' },
        // Add more datacenter IP ranges
      ];

      // This would require IP range checking library
      return {
        isDatacenter: false,
        provider: null,
        type: null
      };
    },

    /**
     * Detect impossible travel (IP velocity check)
     */
    analyzeIPVelocity(previousIP, currentIP, timeDeltaSeconds) {
      // Real-world travel speed limit: ~900 m/s (fastest aircraft)
      const maxDistance = 900 * timeDeltaSeconds; // meters

      // This requires geolocation lookup for IPs
      // Simplified example:
      return {
        distanceBetweenIPs: null,
        timeElapsed: timeDeltaSeconds,
        isPossibleTravel: true,
        suspicion: 0
      };
    },

    /**
     * Multi-IP session tracking
     */
    correlateIPsAcrossSession(ipHistory) {
      const analysis = {
        uniqueIPs: ipHistory.length,
        gapTimes: [],
        velocityAnomalies: [],
        likelyBotScore: 0
      };

      // Analyze gaps and velocities
      for (let i = 1; i < ipHistory.length; i++) {
        const gap = ipHistory[i].time - ipHistory[i - 1].time;
        analysis.gapTimes.push(gap);

        // Quick IP changes (< 1 second) suggest bot activity
        if (gap < 1000) {
          analysis.velocityAnomalies.push({
            between: `${ipHistory[i - 1].ip} → ${ipHistory[i].ip}`,
            gap
          });
        }
      }

      if (analysis.velocityAnomalies.length > 0) {
        analysis.likelyBotScore = 70;
      }

      return analysis;
    }
  };
}

export async function runNetworkIntelligenceChecks() {
  const signals = [];
  const evidence = {};

  // Collect WebRTC data
  const webrtcData = await detectWebRTCIPIndicators();
  evidence.webrtc = webrtcData;

  // Analyze network quality
  const networkAnalysis = analyzeNetworkQuality();
  evidence.networkQuality = networkAnalysis;

  // Detect VPN/Proxy indicators
  const vpnIndicators = detectVPNProxyIndicators();
  evidence.vpnIndicators = vpnIndicators;

  // Check geolocation consistency
  const geoCheck = checkGeoLocationConsistency();
  evidence.geolocation = geoCheck;

  // Analyze HTTP profile
  const httpProfile = analyzeHTTPConnectionProfile();
  evidence.httpProfile = httpProfile;

  // Generate signals
  signals.push(...generateIPSignals(webrtcData, networkAnalysis, vpnIndicators));

  // Add network quality anomaly signals
  if (networkAnalysis.suspicions.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'networkQualityAnomaly',
        label: 'Network Quality Anomalies',
        value: true,
        evidence: networkAnalysis.evidence,
        category: 'environment',
        severity: 'soft',
        weight: 3,
        confidence: 55,
        state: 'suspicious'
      })
    );
  }

  return { signals, evidence };
}

/**
 * Export server-side analyzer for backend integration
 */
export const IPIntelligenceAnalyzer = createServerSideIPAnalyzer();

# app/services/threat_intel.py - FIXED VERSION
"""
Threat Intelligence Service - FIXED IMPORT
External threat intelligence lookup and integration
"""

import aiohttp
import asyncio
import logging
import json
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from ..models.threat import Threat
from ..config import config

logger = logging.getLogger('threat_intelligence')

class ThreatIntelService:
    """External Threat Intelligence Integration"""
    
    def __init__(self):
        self.virustotal_api_key = config.get('threat_intel', {}).get('virustotal_api_key')
        self.cache_ttl = config.get('detection', {}).get('threat_intel_cache_ttl', 3600)
        self.session_cache = {}  # Memory cache for session
        
    async def check_hash_reputation(self, file_hash: str, session: Session) -> Optional[Dict]:
        """Check hash reputation from external sources"""
        try:
            # 1. Check local database first
            local_threat = Threat.check_hash(session, file_hash)
            if local_threat:
                logger.debug(f"Hash found in local database: {file_hash}")
                return {
                    'source': 'Local Database',
                    'threat_id': local_threat.ThreatID,
                    'threat_name': local_threat.ThreatName,
                    'severity': local_threat.Severity,
                    'confidence': float(local_threat.Confidence) if local_threat.Confidence else 0.8,
                    'cached': True
                }
            
            # 2. Check memory cache
            cache_key = f"hash_{file_hash}"
            if cache_key in self.session_cache:
                cache_data = self.session_cache[cache_key]
                if datetime.now() < cache_data['expires']:
                    logger.debug(f"Hash found in memory cache: {file_hash}")
                    return cache_data['result']
                else:
                    del self.session_cache[cache_key]
            
            # 3. Query external sources
            result = await self._query_external_sources(file_hash)
            
            # 4. Cache and store result if threat found
            if result and result.get('is_malicious', False):
                # Cache in memory
                self.session_cache[cache_key] = {
                    'result': result,
                    'expires': datetime.now() + timedelta(seconds=self.cache_ttl)
                }
                
                # Store in database for future use
                await self._store_threat_in_database(file_hash, result, session)
                
                logger.info(f"New threat detected and cached: {file_hash} - {result.get('threat_name')}")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Threat intel lookup failed for {file_hash}: {str(e)}")
            return None
    
    async def check_ip_reputation(self, ip_address: str, session: Session) -> Optional[Dict]:
        """Check IP reputation from external sources"""
        try:
            # 1. Check local database first
            local_threat = Threat.check_ip(session, ip_address)
            if local_threat:
                return {
                    'source': 'Local Database',
                    'threat_id': local_threat.ThreatID,
                    'threat_name': local_threat.ThreatName,
                    'severity': local_threat.Severity,
                    'confidence': float(local_threat.Confidence) if local_threat.Confidence else 0.8,
                    'cached': True
                }
            
            # 2. Query external sources for IP
            result = await self._query_ip_reputation(ip_address)
            
            if result and result.get('is_malicious', False):
                await self._store_threat_in_database(ip_address, result, session, threat_type='IP')
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"IP reputation lookup failed for {ip_address}: {str(e)}")
            return None
    
    async def check_domain_reputation(self, domain: str, session: Session) -> Optional[Dict]:
        """Check domain reputation from external sources"""
        try:
            local_threat = Threat.check_domain(session, domain)
            if local_threat:
                return {
                    'source': 'Local Database',
                    'threat_id': local_threat.ThreatID,
                    'threat_name': local_threat.ThreatName,
                    'severity': local_threat.Severity,
                    'confidence': float(local_threat.Confidence) if local_threat.Confidence else 0.8,
                    'cached': True
                }
            
            result = await self._query_domain_reputation(domain)
            
            if result and result.get('is_malicious', False):
                await self._store_threat_in_database(domain, result, session, threat_type='Domain')
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Domain reputation lookup failed for {domain}: {str(e)}")
            return None
    
    async def _query_external_sources(self, file_hash: str) -> Optional[Dict]:
        """Query external threat intelligence sources"""
        try:
            results = []
            
            # VirusTotal
            if self.virustotal_api_key:
                vt_result = await self._check_virustotal_hash(file_hash)
                if vt_result:
                    results.append(vt_result)
            
            # Add other sources here
            # malware_bazaar_result = await self._check_malware_bazaar(file_hash)
            # if malware_bazaar_result:
            #     results.append(malware_bazaar_result)
            
            # Combine results and return best match
            return self._combine_threat_results(results)
            
        except Exception as e:
            logger.error(f"External source query failed: {str(e)}")
            return None
    
    async def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Check hash against VirusTotal API"""
        try:
            if not self.virustotal_api_key:
                logger.debug("VirusTotal API key not configured")
                return None
            
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': file_hash
            }
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_virustotal_response(data)
                    elif response.status == 204:
                        logger.debug("VirusTotal rate limit exceeded")
                        return None
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None
                        
        except asyncio.TimeoutError:
            logger.warning("VirusTotal API timeout")
            return None
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return None
    
    def _parse_virustotal_response(self, data: Dict) -> Optional[Dict]:
        """Parse VirusTotal API response"""
        try:
            if data.get('response_code') != 1:
                return None  # File not found
            
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            
            if positives > 0:
                # Determine severity based on detection ratio
                detection_ratio = positives / total if total > 0 else 0
                
                if detection_ratio >= 0.7:
                    severity = 'Critical'
                elif detection_ratio >= 0.4:
                    severity = 'High'
                elif detection_ratio >= 0.2:
                    severity = 'Medium'
                else:
                    severity = 'Low'
                
                # Get most common detection name
                scans = data.get('scans', {})
                detection_names = []
                for scanner, result in scans.items():
                    if result.get('detected') and result.get('result'):
                        detection_names.append(result['result'])
                
                threat_name = self._get_most_common_detection(detection_names) or 'Unknown Malware'
                
                return {
                    'source': 'VirusTotal',
                    'threat_name': threat_name,
                    'severity': severity,
                    'confidence': min(0.9, detection_ratio + 0.1),
                    'is_malicious': True,
                    'detections': f"{positives}/{total}",
                    'scan_date': data.get('scan_date'),
                    'permalink': data.get('permalink')
                }
            
            return None
            
        except Exception as e:
            logger.error(f"VirusTotal response parsing failed: {str(e)}")
            return None
    
    def _get_most_common_detection(self, detection_names: List[str]) -> Optional[str]:
        """Get most common detection name from list"""
        if not detection_names:
            return None
        
        # Simple frequency count
        from collections import Counter
        counter = Counter(detection_names)
        most_common = counter.most_common(1)
        return most_common[0][0] if most_common else detection_names[0]
    
    async def _query_ip_reputation(self, ip_address: str) -> Optional[Dict]:
        """Query IP reputation from external sources"""
        try:
            # Implement IP reputation checks
            # Example: AbuseIPDB, VirusTotal IP lookup, etc.
            logger.debug(f"IP reputation check not implemented: {ip_address}")
            return None
            
        except Exception as e:
            logger.error(f"IP reputation query failed: {str(e)}")
            return None
    
    async def _query_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Query domain reputation from external sources"""
        try:
            # Implement domain reputation checks
            logger.debug(f"Domain reputation check not implemented: {domain}")
            return None
            
        except Exception as e:
            logger.error(f"Domain reputation query failed: {str(e)}")
            return None
    
    def _combine_threat_results(self, results: List[Dict]) -> Optional[Dict]:
        """Combine results from multiple sources"""
        if not results:
            return None
        
        # For now, return first malicious result
        # Can be enhanced to combine multiple sources
        for result in results:
            if result.get('is_malicious', False):
                return result
        
        return None
    
    async def _store_threat_in_database(self, threat_value: str, threat_data: Dict, 
                                      session: Session, threat_type: str = 'Hash'):
        """Store discovered threat in local database"""
        try:
            # Check if already exists
            existing = Threat.get_by_value(session, threat_value)
            if existing:
                return existing
            
            # Create new threat
            threat = Threat.create_threat(
                threat_name=threat_data.get('threat_name', 'Unknown'),
                threat_type=threat_type,
                threat_value=threat_value,
                threat_category='External Intelligence',
                severity=threat_data.get('severity', 'Medium'),
                description=f"Detected by {threat_data.get('source', 'External')} - {threat_data.get('detections', '')}",
                threat_source=threat_data.get('source', 'External'),
                confidence=threat_data.get('confidence', 0.7)
            )
            
            session.add(threat)
            session.commit()
            
            logger.info(f"Stored new threat: {threat_value} - {threat_data.get('threat_name')}")
            return threat
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store threat in database: {str(e)}")
            return None
    
    async def bulk_check_hashes(self, hashes: List[str], session: Session) -> Dict[str, Dict]:
        """Bulk check multiple hashes"""
        results = {}
        
        try:
            # Process in batches to avoid overwhelming APIs
            batch_size = 4  # VirusTotal free tier limit
            for i in range(0, len(hashes), batch_size):
                batch = hashes[i:i + batch_size]
                
                # Process batch concurrently
                tasks = [self.check_hash_reputation(hash_val, session) for hash_val in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for hash_val, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"Bulk check failed for {hash_val}: {result}")
                        results[hash_val] = None
                    else:
                        results[hash_val] = result
                
                # Rate limiting delay
                if i + batch_size < len(hashes):
                    await asyncio.sleep(15)  # 15 second delay between batches
            
            return results
            
        except Exception as e:
            logger.error(f"Bulk hash check failed: {str(e)}")
            return results
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        total_cached = len(self.session_cache)
        expired_count = sum(1 for data in self.session_cache.values() 
                          if datetime.now() >= data['expires'])
        
        return {
            'total_cached': total_cached,
            'expired_count': expired_count,
            'active_count': total_cached - expired_count,
            'cache_ttl': self.cache_ttl
        }
    
    def clear_expired_cache(self):
        """Clear expired cache entries"""
        now = datetime.now()
        expired_keys = [key for key, data in self.session_cache.items() 
                       if now >= data['expires']]
        
        for key in expired_keys:
            del self.session_cache[key]
        
        if expired_keys:
            logger.debug(f"Cleared {len(expired_keys)} expired cache entries")

# Global service instance
threat_intel_service = ThreatIntelService()
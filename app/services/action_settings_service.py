"""
Action Settings Service
Quản lý action settings cho agents
"""

import json
import logging
import redis
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from ..models.agent import Agent

logger = logging.getLogger('action_settings')

class ActionSettingsService:
    """Service for managing action settings for agents"""
    
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
    
    def get_action_settings(self, agent_id: str) -> Dict:
        """Get action settings for agent"""
        try:
            key = f"action_settings:{agent_id}"
            val = self.redis_client.get(key)
            print(f"[DEBUG][get_action_settings] key={key}, value={val}")
            if val:
                settings = json.loads(val)
                return settings
        except Exception as e:
            logger.error(f"Failed to get action settings for agent {agent_id}: {str(e)}")
        # Nếu không có dữ liệu thì trả về object rỗng
        print(f"[DEBUG][get_action_settings] return empty for {agent_id}")
        return {}
    
    def update_action_settings(self, agent_id: str, action_settings: Dict) -> Tuple[bool, str]:
        """Update action settings for agent"""
        try:
            # Validate settings
            validation_result = self._validate_action_settings(action_settings)
            if not validation_result[0]:
                print(f"[DEBUG][update_action_settings] validation failed: {validation_result}")
                return validation_result
            
            # Add metadata
            action_settings['updated_at'] = datetime.now().isoformat()
            action_settings['agent_id'] = agent_id
            
            # Store in Redis
            key = f"action_settings:{agent_id}"
            self.redis_client.set(key, json.dumps(action_settings))
            print(f"[DEBUG][update_action_settings] key={key}, value={action_settings}")
            
            # Log the update
            global_mode = action_settings.get('globalActionMode', 'alert_only')
            event_actions = action_settings.get('eventActions', [])
            enabled_count = len([ea for ea in event_actions if ea.get('enabled')])
            
            logger.info(f"Action settings updated for agent {agent_id}: {global_mode}")
            logger.info(f"Event actions: {enabled_count} enabled")
            
            return True, "Action settings updated successfully"
            
        except Exception as e:
            error_msg = f"Failed to update action settings for agent {agent_id}: {str(e)}"
            logger.error(error_msg)
            print(f"[DEBUG][update_action_settings] error: {error_msg}")
            return False, error_msg
    
    def delete_action_settings(self, agent_id: str) -> Tuple[bool, str]:
        """Delete action settings for agent"""
        try:
            key = f"action_settings:{agent_id}"
            self.redis_client.delete(key)
            
            logger.info(f"Action settings deleted for agent {agent_id}")
            return True, "Action settings deleted successfully"
            
        except Exception as e:
            error_msg = f"Failed to delete action settings for agent {agent_id}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_action_status(self, agent_id: str) -> Dict:
        """Get action status and statistics for agent"""
        try:
            settings = self.get_action_settings(agent_id)
            global_mode = settings.get('globalActionMode', 'alert_only')
            event_actions = settings.get('eventActions', [])
            
            enabled_actions = [ea for ea in event_actions if ea.get('enabled')]
            
            # Get action execution stats (simplified - in production you'd query logs)
            action_stats = self._get_action_execution_stats(agent_id)
            
            return {
                "agent_id": agent_id,
                "global_action_mode": global_mode,
                "enabled_actions_count": len(enabled_actions),
                "enabled_actions": [
                    {
                        'event_type': ea['event_type'],
                        'action': ea['action'],
                        'severity': ea['severity']
                    } for ea in enabled_actions
                ],
                "action_stats": action_stats,
                "status": settings.get('status', 'default'),
                "last_updated": settings.get('last_updated', 'never')
            }
            
        except Exception as e:
            logger.error(f"Failed to get action status for agent {agent_id}: {str(e)}")
            return {"error": str(e)}
    
    def should_execute_action(self, agent_id: str, event_type: str, severity: str) -> Tuple[bool, Optional[Dict]]:
        """Check if action should be executed for given event type and severity"""
        try:
            settings = self.get_action_settings(agent_id)
            
            # Check global mode
            global_mode = settings.get('globalActionMode', 'alert_only')
            if global_mode == 'alert_only':
                return False, None
            
            # Find matching event action - KIỂM TRA CẢ 3 ĐIỀU KIỆN CÙNG LÚC
            event_actions = settings.get('eventActions', [])
            for ea in event_actions:
                # ĐIỀU KIỆN 1 && ĐIỀU KIỆN 2 && ĐIỀU KIỆN 3
                if (ea.get('enabled', False) and 
                    ea.get('event_type') == event_type and 
                    severity in ea.get('severity', [])):
                    return True, ea
            
            return False, None
            
        except Exception as e:
            logger.error(f"Error checking action execution for agent {agent_id}: {str(e)}")
            return False, None
    
    def get_all_agents_action_status(self, session: Session) -> List[Dict]:
        """Get action status for all agents"""
        try:
            agents = Agent.get_all_agents(session)
            status_list = []
            
            for agent in agents:
                agent_status = self.get_action_status(str(agent.AgentID))
                agent_status['hostname'] = agent.HostName
                agent_status['agent_status'] = agent.Status
                status_list.append(agent_status)
            
            return status_list
            
        except Exception as e:
            logger.error(f"Failed to get all agents action status: {str(e)}")
            return []
    
    def _validate_action_settings(self, action_settings: Dict) -> Tuple[bool, str]:
        """Validate action settings structure"""
        try:
            if not isinstance(action_settings, dict):
                return False, "Invalid action settings format"
            
            global_action_mode = action_settings.get('globalActionMode')
            if global_action_mode not in ['alert_only', 'alert_and_action']:
                return False, "Invalid globalActionMode"
            
            event_actions = action_settings.get('eventActions', [])
            if not isinstance(event_actions, list):
                return False, "Invalid eventActions format"
            
            # Validate each event action
            for ea in event_actions:
                if not isinstance(ea, dict):
                    return False, "Invalid event action format"
                
                required_fields = ['event_type', 'enabled', 'action', 'severity']
                for field in required_fields:
                    if field not in ea:
                        return False, f"Missing required field: {field}"
                
                if ea['event_type'] not in ['Process', 'Network', 'File', 'Registry']:
                    return False, f"Invalid event_type: {ea['event_type']}"
                
                if not isinstance(ea['enabled'], bool):
                    return False, "enabled must be boolean"
                
                if not isinstance(ea['severity'], list):
                    return False, "severity must be list"
                
                for severity in ea['severity']:
                    if severity not in ['Low', 'Medium', 'High', 'Critical']:
                        return False, f"Invalid severity: {severity}"
            
            return True, "Validation successful"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def _get_default_settings(self) -> Dict:
        """Get default action settings"""
        return {
            'globalActionMode': 'alert_only',
            'eventActions': [
                {
                    'event_type': 'Process',
                    'enabled': False,
                    'action': 'kill_process',
                    'severity': ['High', 'Critical'],
                    'config': {}
                },
                {
                    'event_type': 'Network',
                    'enabled': False,
                    'action': 'block_network',
                    'severity': ['High', 'Critical'],
                    'config': {}
                },
                {
                    'event_type': 'File',
                    'enabled': False,
                    'action': 'quarantine_file',
                    'severity': ['High', 'Critical'],
                    'config': {}
                },
                {
                    'event_type': 'Registry',
                    'enabled': False,
                    'action': 'block_registry',
                    'severity': ['High', 'Critical'],
                    'config': {}
                }
            ],
            'status': 'default',
            'last_updated': 'never'
        }
    
    def _get_action_execution_stats(self, agent_id: str) -> Dict:
        """Get action execution statistics for agent"""
        # This is a simplified implementation
        # In production, you'd query logs or database for actual stats
        return {
            'total_actions_executed': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'last_action_executed': None,
            'actions_by_type': {
                'kill_process': 0,
                'block_network': 0,
                'quarantine_file': 0,
                'block_registry': 0
            }
        }

# Global service instance
action_settings_service = ActionSettingsService() 
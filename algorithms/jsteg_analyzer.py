"""
JSteg Analysis Algorithm
Detects JSteg steganography in JPEG images by analyzing DCT coefficient modifications
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

class JStegAnalyzer:
    """JSteg steganography detection algorithm for JPEG images"""
    
    def __init__(self):
        self.block_size = 8
        self.suspicious_threshold = 0.15  # 15% of coefficients showing JSteg pattern
        self.coefficient_threshold = 3    # Focus on coefficients with absolute value >= 3
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform JSteg analysis on JPEG image"""
        try:
            with Image.open(file_path) as img:
                # Check if JPEG format
                if img.format != 'JPEG':
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'JSteg analysis only applicable to JPEG images'
                    }
                
                # Convert to grayscale for DCT analysis
                if img.mode != 'L':
                    img = img.convert('L')
                
                img_array = np.array(img, dtype=np.float32)
                height, width = img_array.shape
                
                # Analyze DCT blocks for JSteg patterns
                jsteg_indicators = []
                total_coefficients = 0
                suspicious_coefficients = 0
                analyzed_blocks = 0
                
                # Process 8x8 blocks
                for y in range(0, height - self.block_size + 1, self.block_size):
                    for x in range(0, width - self.block_size + 1, self.block_size):
                        block = img_array[y:y+self.block_size, x:x+self.block_size]
                        
                        # Apply DCT
                        dct_block = self._dct2d(block)
                        
                        # Analyze for JSteg patterns
                        block_indicators = self._detect_jsteg_patterns(dct_block)
                        
                        if block_indicators['total_analyzed'] > 0:
                            jsteg_indicators.append(block_indicators)
                            total_coefficients += block_indicators['total_analyzed']
                            suspicious_coefficients += block_indicators['suspicious_count']
                            analyzed_blocks += 1
                
                if total_coefficients == 0:
                    return {
                        'status': 'error',
                        'error': 'No DCT coefficients could be analyzed for JSteg patterns'
                    }
                
                # Calculate overall suspicion rate
                suspicion_rate = suspicious_coefficients / total_coefficients
                confidence = min(95.0, suspicion_rate * 300)  # Scale to percentage
                
                # Additional statistical test
                chi_square_result = self._jsteg_chi_square_test(jsteg_indicators)
                
                # Generate verdict
                if suspicion_rate > self.suspicious_threshold:
                    status = 'found'
                    message = f'JSteg steganography detected: {suspicious_coefficients}/{total_coefficients} suspicious coefficients'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(suspicious_coefficients)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_coefficients': suspicious_coefficients,
                            'total_coefficients': total_coefficients,
                            'suspicion_rate': round(suspicion_rate * 100, 2)
                        },
                        'details': {
                            'analyzed_blocks': analyzed_blocks,
                            'chi_square': chi_square_result
                        }
                    }
                
                elif suspicion_rate > 0.05:  # 5-15% suspicious coefficients
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak JSteg signals: {suspicious_coefficients}/{total_coefficients} coefficients',
                        'details': {
                            'suspicion_rate': round(suspicion_rate * 100, 2),
                            'analyzed_blocks': analyzed_blocks
                        }
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No JSteg steganography detected',
                        'details': {
                            'analyzed_blocks': analyzed_blocks,
                            'total_coefficients': total_coefficients
                        }
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'JSteg analysis failed: {str(e)}'
            }
    
    def _dct2d(self, block: np.ndarray) -> np.ndarray:
        """Compute 2D DCT of an 8x8 block"""
        try:
            N = self.block_size
            dct_block = np.zeros((N, N))
            
            for u in range(N):
                for v in range(N):
                    sum_val = 0.0
                    for x in range(N):
                        for y in range(N):
                            sum_val += block[x, y] * math.cos((2*x + 1) * u * math.pi / (2*N)) * \
                                      math.cos((2*y + 1) * v * math.pi / (2*N))
                    
                    # Apply normalization factors
                    cu = 1/math.sqrt(2) if u == 0 else 1
                    cv = 1/math.sqrt(2) if v == 0 else 1
                    
                    dct_block[u, v] = (2/N) * cu * cv * sum_val
            
            return dct_block
            
        except Exception:
            return np.zeros((self.block_size, self.block_size))
    
    def _detect_jsteg_patterns(self, dct_block: np.ndarray) -> Dict[str, int]:
        """Detect JSteg-specific patterns in DCT coefficients"""
        try:
            # JSteg modifies DCT coefficients with absolute value >= 3
            # It uses LSB modification, so we look for even/odd distribution anomalies
            
            # Get all AC coefficients (exclude DC at [0,0])
            ac_coeffs = []
            for u in range(self.block_size):
                for v in range(self.block_size):
                    if u != 0 or v != 0:  # Skip DC coefficient
                        coeff = int(round(dct_block[u, v]))
                        if abs(coeff) >= self.coefficient_threshold:
                            ac_coeffs.append(coeff)
            
            if len(ac_coeffs) == 0:
                return {'total_analyzed': 0, 'suspicious_count': 0}
            
            # Analyze coefficient distribution for JSteg patterns
            suspicious_count = 0
            
            # JSteg creates specific patterns in coefficient pairs
            for i in range(0, len(ac_coeffs) - 1, 2):
                coeff1 = ac_coeffs[i]
                coeff2 = ac_coeffs[i + 1] if i + 1 < len(ac_coeffs) else 0
                
                # Check for JSteg-specific modifications
                # JSteg tends to create certain patterns in coefficient pairs
                if self._is_jsteg_pattern(coeff1, coeff2):
                    suspicious_count += 1
            
            return {
                'total_analyzed': len(ac_coeffs) // 2,  # Analyzed in pairs
                'suspicious_count': suspicious_count
            }
            
        except Exception:
            return {'total_analyzed': 0, 'suspicious_count': 0}
    
    def _is_jsteg_pattern(self, coeff1: int, coeff2: int) -> bool:
        """Check if coefficient pair shows JSteg-specific pattern"""
        try:
            # JSteg-specific pattern detection
            # Look for LSB modifications in coefficient pairs
            
            # Pattern 1: Both coefficients modified (LSB pattern)
            if abs(coeff1) >= self.coefficient_threshold and abs(coeff2) >= self.coefficient_threshold:
                # Check if LSBs show unnatural pattern
                lsb1 = abs(coeff1) % 2
                lsb2 = abs(coeff2) % 2
                
                # JSteg creates specific LSB relationships
                if (lsb1 == lsb2) and (abs(abs(coeff1) - abs(coeff2)) <= 2):
                    return True
            
            # Pattern 2: Coefficient value distribution anomaly
            if abs(coeff1) >= self.coefficient_threshold:
                # JSteg avoids certain coefficient values
                if abs(coeff1) % 4 == 0 and abs(coeff1) > 8:  # Suspicious even patterns
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _jsteg_chi_square_test(self, indicators: List[Dict[str, int]]) -> Dict[str, float]:
        """Perform chi-square test for JSteg detection"""
        try:
            if not indicators:
                return {'chi_square': 0.0, 'p_value': 1.0}
            
            # Collect all suspicious counts for statistical test
            suspicious_counts = [ind['suspicious_count'] for ind in indicators if ind['total_analyzed'] > 0]
            
            if len(suspicious_counts) < 2:
                return {'chi_square': 0.0, 'p_value': 1.0}
            
            # Simple chi-square test for distribution
            observed = np.array(suspicious_counts)
            expected = np.mean(observed)
            
            if expected > 0:
                chi_square = np.sum((observed - expected) ** 2) / expected
            else:
                chi_square = 0.0
            
            # Rough p-value estimation (simplified)
            p_value = 1.0 / (1.0 + chi_square) if chi_square > 0 else 1.0
            
            return {'chi_square': float(chi_square), 'p_value': float(p_value)}
            
        except Exception:
            return {'chi_square': 0.0, 'p_value': 1.0}
    
    def _estimate_hidden_data_size(self, suspicious_coefficients: int) -> int:
        """Estimate size of data hidden using JSteg"""
        try:
            # JSteg typically embeds 1 bit per modified coefficient
            estimated_bits = suspicious_coefficients
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
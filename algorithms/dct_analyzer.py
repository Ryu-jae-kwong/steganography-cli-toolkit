"""
DCT (Discrete Cosine Transform) Analysis Algorithm
Detects steganography in JPEG images using DCT coefficient analysis
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, Optional
import math

class DCTAnalyzer:
    """DCT-based steganography detection for JPEG images"""
    
    def __init__(self):
        self.block_size = 8
        self.threshold_variance = 2.5
        self.threshold_histogram = 15.0
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform DCT analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Check if JPEG format
                if img.format != 'JPEG':
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'DCT analysis only applicable to JPEG images'
                    }
                
                # Convert to grayscale for DCT analysis
                if img.mode != 'L':
                    img = img.convert('L')
                
                img_array = np.array(img, dtype=np.float32)
                height, width = img_array.shape
                
                # Perform DCT block analysis
                suspicious_blocks = 0
                total_blocks = 0
                coefficient_anomalies = []
                
                # Process 8x8 blocks
                for y in range(0, height - self.block_size + 1, self.block_size):
                    for x in range(0, width - self.block_size + 1, self.block_size):
                        block = img_array[y:y+self.block_size, x:x+self.block_size]
                        
                        # Apply DCT
                        dct_block = self._dct2d(block)
                        
                        # Analyze coefficients
                        anomaly_score = self._analyze_dct_coefficients(dct_block)
                        
                        if anomaly_score > self.threshold_variance:
                            suspicious_blocks += 1
                            coefficient_anomalies.append({
                                'position': (x, y),
                                'anomaly_score': anomaly_score
                            })
                        
                        total_blocks += 1
                
                # Calculate overall statistics
                if total_blocks == 0:
                    return {
                        'status': 'error',
                        'error': 'No DCT blocks could be analyzed'
                    }
                
                suspicion_ratio = suspicious_blocks / total_blocks
                confidence = min(95.0, suspicion_ratio * 200.0)  # Scale to percentage
                
                # Determine verdict
                if suspicion_ratio > 0.15:  # More than 15% suspicious blocks
                    status = 'found'
                    message = f'DCT-based steganography detected in {suspicious_blocks}/{total_blocks} blocks'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(suspicious_blocks)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_blocks': suspicious_blocks,
                            'total_blocks': total_blocks,
                            'suspicion_ratio': round(suspicion_ratio * 100, 2)
                        },
                        'details': {
                            'anomalies': coefficient_anomalies[:10]  # Limit to first 10
                        }
                    }
                
                elif suspicion_ratio > 0.05:  # 5-15% suspicious blocks
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak DCT signal in {suspicious_blocks}/{total_blocks} blocks',
                        'details': {
                            'suspicion_ratio': round(suspicion_ratio * 100, 2),
                            'total_blocks': total_blocks
                        }
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No DCT-based steganography detected',
                        'details': {
                            'suspicious_blocks': suspicious_blocks,
                            'total_blocks': total_blocks
                        }
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'DCT analysis failed: {str(e)}'
            }
    
    def _dct2d(self, block: np.ndarray) -> np.ndarray:
        """Compute 2D DCT of an 8x8 block"""
        try:
            # Simple DCT implementation
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
    
    def _analyze_dct_coefficients(self, dct_block: np.ndarray) -> float:
        """Analyze DCT coefficients for steganography indicators"""
        try:
            # Focus on AC coefficients (exclude DC component at [0,0])
            ac_coeffs = dct_block[1:, :].flatten().tolist() + dct_block[0, 1:].flatten().tolist()
            
            if not ac_coeffs:
                return 0.0
            
            # Calculate coefficient statistics
            coeff_array = np.array(ac_coeffs)
            
            # 1. Variance test - hidden data increases variance
            variance = np.var(coeff_array)
            
            # 2. Zero coefficient ratio - steganography affects zero/non-zero ratio
            zero_count = np.sum(coeff_array == 0)
            non_zero_count = len(coeff_array) - zero_count
            zero_ratio = zero_count / len(coeff_array) if len(coeff_array) > 0 else 0
            
            # 3. Small coefficient analysis - look for unnatural patterns
            small_coeffs = coeff_array[np.abs(coeff_array) <= 1]
            small_ratio = len(small_coeffs) / len(coeff_array) if len(coeff_array) > 0 else 0
            
            # Calculate anomaly score
            anomaly_score = 0.0
            
            # High variance is suspicious
            if variance > 10.0:
                anomaly_score += min(5.0, variance / 2.0)
            
            # Unusual zero ratios are suspicious
            if zero_ratio < 0.3 or zero_ratio > 0.8:
                anomaly_score += abs(zero_ratio - 0.55) * 10
            
            # Unusual small coefficient ratios
            if small_ratio < 0.4 or small_ratio > 0.9:
                anomaly_score += abs(small_ratio - 0.65) * 5
            
            return anomaly_score
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, suspicious_blocks: int) -> int:
        """Estimate size of hidden data based on suspicious blocks"""
        # Each block can theoretically hide several bits
        # Conservative estimate: 2-4 bits per suspicious block
        estimated_bits = suspicious_blocks * 3
        estimated_bytes = max(1, estimated_bits // 8)
        
        return estimated_bytes
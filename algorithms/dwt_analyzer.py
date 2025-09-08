"""
DWT (Discrete Wavelet Transform) Analysis Algorithm
Detects steganography in wavelet coefficients and high-frequency components
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

try:
    import pywt
    DWT_AVAILABLE = True
except ImportError:
    DWT_AVAILABLE = False

class DWTAnalyzer:
    """DWT-based steganography detection algorithm"""
    
    def __init__(self):
        self.noise_threshold = 0.4        # Threshold for noise pattern detection
        self.coefficient_threshold = 0.35  # Threshold for coefficient anomalies
        self.decomposition_levels = 3      # Number of wavelet decomposition levels
        self.wavelet_types = ['db4', 'haar', 'bior4.4']  # Wavelets to test
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform DWT analysis on image file"""
        if not DWT_AVAILABLE:
            return {
                'status': 'error',
                'error': 'PyWavelets library not available. Install with: pip install PyWavelets'
            }
        
        try:
            with Image.open(file_path) as img:
                # Convert to grayscale for wavelet analysis
                if img.mode != 'L':
                    if img.mode == 'RGBA':
                        img = img.convert('RGB')
                    gray_img = img.convert('L')
                else:
                    gray_img = img
                
                img_array = np.array(gray_img, dtype=np.float32)
                height, width = img_array.shape
                
                # Analyze with multiple wavelets
                wavelet_results = []
                total_anomaly_score = 0.0
                suspicious_wavelets = 0
                
                for wavelet in self.wavelet_types:
                    try:
                        wavelet_anomaly = self._analyze_wavelet_coefficients(img_array, wavelet)
                        is_suspicious = wavelet_anomaly > self.coefficient_threshold
                        
                        if is_suspicious:
                            suspicious_wavelets += 1
                        
                        total_anomaly_score += wavelet_anomaly
                        
                        wavelet_results.append({
                            'wavelet': wavelet,
                            'anomaly_score': wavelet_anomaly,
                            'is_suspicious': is_suspicious
                        })
                        
                    except Exception as e:
                        wavelet_results.append({
                            'wavelet': wavelet,
                            'error': str(e)
                        })
                
                # Calculate overall confidence
                avg_anomaly_score = total_anomaly_score / len(self.wavelet_types)
                confidence = min(95.0, avg_anomaly_score * 150)  # Scale to percentage
                
                # Additional high-frequency analysis
                hf_analysis = self._analyze_high_frequency_patterns(img_array)
                
                # Generate verdict
                if suspicious_wavelets >= 2:
                    status = 'found'
                    message = f'DWT steganography detected in {suspicious_wavelets} wavelets'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(height, width, avg_anomaly_score)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_wavelets': suspicious_wavelets,
                            'avg_anomaly_score': round(avg_anomaly_score, 3)
                        },
                        'details': {
                            'wavelets': wavelet_results,
                            'high_frequency': hf_analysis
                        }
                    }
                
                elif suspicious_wavelets == 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak DWT signals in {suspicious_wavelets} wavelet',
                        'details': {
                            'wavelets': wavelet_results,
                            'high_frequency': hf_analysis
                        }
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No DWT-based steganography detected',
                        'details': {
                            'wavelets': wavelet_results,
                            'high_frequency': hf_analysis
                        }
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'DWT analysis failed: {str(e)}'
            }
    
    def _analyze_wavelet_coefficients(self, img_array: np.ndarray, wavelet: str) -> float:
        """Analyze wavelet coefficients for steganographic anomalies"""
        try:
            anomaly_score = 0.0
            
            # Perform multi-level wavelet decomposition
            coeffs = pywt.wavedec2(img_array, wavelet, level=self.decomposition_levels)
            
            # Analyze each decomposition level
            for level_idx, level_coeffs in enumerate(coeffs[1:], 1):  # Skip approximation coefficients
                if isinstance(level_coeffs, tuple):
                    # Detail coefficients: (cH, cV, cD)
                    for detail_idx, detail in enumerate(level_coeffs):
                        detail_anomaly = self._analyze_detail_coefficients(detail, level_idx, detail_idx)
                        anomaly_score += detail_anomaly * (0.4 / (level_idx ** 0.5))  # Weight by level
            
            # Analyze coefficient distribution
            all_details = []
            for level_coeffs in coeffs[1:]:
                if isinstance(level_coeffs, tuple):
                    for detail in level_coeffs:
                        all_details.extend(detail.flatten())
            
            if all_details:
                distribution_anomaly = self._analyze_coefficient_distribution(np.array(all_details))
                anomaly_score += distribution_anomaly * 0.2
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_detail_coefficients(self, detail_coeffs: np.ndarray, level: int, detail_type: int) -> float:
        """Analyze detail coefficients for anomalies"""
        try:
            if detail_coeffs.size == 0:
                return 0.0
            
            anomaly_score = 0.0
            
            # Test 1: Unusual coefficient magnitude patterns
            magnitude_anomaly = self._detect_magnitude_anomalies(detail_coeffs)
            anomaly_score += magnitude_anomaly * 0.4
            
            # Test 2: Statistical distribution anomalies
            stats_anomaly = self._analyze_coefficient_statistics(detail_coeffs)
            anomaly_score += stats_anomaly * 0.3
            
            # Test 3: Local correlation patterns
            correlation_anomaly = self._analyze_local_correlations(detail_coeffs)
            anomaly_score += correlation_anomaly * 0.3
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _detect_magnitude_anomalies(self, coeffs: np.ndarray) -> float:
        """Detect unusual magnitude patterns in coefficients"""
        try:
            if coeffs.size < 10:
                return 0.0
            
            # Calculate coefficient magnitudes
            magnitudes = np.abs(coeffs.flatten())
            
            anomaly_score = 0.0
            
            # Test 1: Too many small coefficients (oversmoothing)
            small_coeffs = np.sum(magnitudes < 0.1)
            small_ratio = small_coeffs / len(magnitudes)
            
            if small_ratio > 0.8:  # More than 80% very small
                anomaly_score += (small_ratio - 0.8) * 2
            
            # Test 2: Unusual large coefficient distribution
            large_coeffs = magnitudes[magnitudes > np.percentile(magnitudes, 95)]
            if len(large_coeffs) > 0:
                large_std = np.std(large_coeffs)
                large_mean = np.mean(large_coeffs)
                
                if large_mean > 0:
                    cv = large_std / large_mean
                    if cv < 0.3:  # Too uniform large coefficients
                        anomaly_score += (0.3 - cv)
            
            # Test 3: Artificial patterns in coefficient signs
            sign_changes = 0
            signs = np.sign(coeffs.flatten())
            for i in range(len(signs) - 1):
                if signs[i] != signs[i + 1]:
                    sign_changes += 1
            
            expected_changes = len(signs) * 0.5  # Random expectation
            if expected_changes > 0:
                sign_ratio = sign_changes / expected_changes
                if sign_ratio < 0.7 or sign_ratio > 1.3:  # Too regular or too chaotic
                    anomaly_score += min(0.3, abs(sign_ratio - 1.0) * 0.5)
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_coefficient_statistics(self, coeffs: np.ndarray) -> float:
        """Analyze statistical properties of coefficients"""
        try:
            flat_coeffs = coeffs.flatten()
            if len(flat_coeffs) < 5:
                return 0.0
            
            anomaly_score = 0.0
            
            # Calculate basic statistics
            mean_coeff = np.mean(flat_coeffs)
            std_coeff = np.std(flat_coeffs)
            
            # Test 1: Unusual mean (should be close to 0 for detail coefficients)
            if abs(mean_coeff) > 0.5:
                anomaly_score += min(0.4, abs(mean_coeff) / 2)
            
            # Test 2: Unusual variance
            # Natural images have certain expected variance patterns
            if std_coeff < 0.1:  # Too little variation
                anomaly_score += (0.1 - std_coeff) * 3
            elif std_coeff > 10:  # Too much variation
                anomaly_score += min(0.3, (std_coeff - 10) / 20)
            
            # Test 3: Distribution shape (using skewness approximation)
            if std_coeff > 0:
                sorted_coeffs = np.sort(flat_coeffs)
                median_coeff = np.median(sorted_coeffs)
                
                # Skewness indicator
                skew_indicator = abs(mean_coeff - median_coeff) / std_coeff
                if skew_indicator > 0.5:  # Highly skewed
                    anomaly_score += min(0.2, skew_indicator - 0.5)
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_local_correlations(self, coeffs: np.ndarray) -> float:
        """Analyze local correlation patterns in coefficients"""
        try:
            if coeffs.size < 9:  # Need at least 3x3
                return 0.0
            
            height, width = coeffs.shape
            anomaly_score = 0.0
            
            # Analyze correlation in 2x2 blocks
            correlations = []
            for y in range(0, height - 1, 2):
                for x in range(0, width - 1, 2):
                    block = coeffs[y:y+2, x:x+2]
                    if block.size == 4:
                        block_flat = block.flatten()
                        if np.std(block_flat) > 1e-10:  # Avoid division by zero
                            # Calculate local correlation
                            corr_matrix = np.corrcoef(block_flat[:2], block_flat[2:])
                            if not np.isnan(corr_matrix[0, 1]):
                                correlations.append(abs(corr_matrix[0, 1]))
            
            if correlations:
                avg_correlation = np.mean(correlations)
                
                # Very high correlation (too smooth) or very low (too noisy) is suspicious
                if avg_correlation > 0.8:
                    anomaly_score += (avg_correlation - 0.8) * 2
                elif avg_correlation < 0.1:
                    anomaly_score += (0.1 - avg_correlation) * 1.5
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_coefficient_distribution(self, all_coeffs: np.ndarray) -> float:
        """Analyze overall coefficient distribution across all levels"""
        try:
            if len(all_coeffs) < 100:
                return 0.0
            
            anomaly_score = 0.0
            
            # Calculate histogram of coefficients
            hist, bins = np.histogram(all_coeffs, bins=50, density=True)
            
            # Test 1: Distribution entropy
            hist_nonzero = hist[hist > 0]
            if len(hist_nonzero) > 1:
                entropy = -np.sum(hist_nonzero * np.log2(hist_nonzero + 1e-10))
                max_entropy = math.log2(len(hist_nonzero))
                
                if max_entropy > 0:
                    normalized_entropy = entropy / max_entropy
                    # Very uniform (high entropy) can be suspicious
                    if normalized_entropy > 0.95:
                        anomaly_score += (normalized_entropy - 0.95) * 4
            
            # Test 2: Central concentration
            center_range = np.sum(hist[20:30]) / np.sum(hist)  # Middle 20% of range
            if center_range > 0.7:  # Too concentrated in center
                anomaly_score += (center_range - 0.7) * 1.5
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_high_frequency_patterns(self, img_array: np.ndarray) -> Dict[str, float]:
        """Analyze high-frequency patterns for additional insights"""
        try:
            # Simple high-frequency analysis using gradients
            grad_x = np.gradient(img_array, axis=1)
            grad_y = np.gradient(img_array, axis=0)
            
            gradient_magnitude = np.sqrt(grad_x**2 + grad_y**2)
            
            # Calculate statistics
            hf_mean = np.mean(gradient_magnitude)
            hf_std = np.std(gradient_magnitude)
            hf_max = np.max(gradient_magnitude)
            
            # Normalize for comparison
            total_pixels = img_array.size
            
            return {
                'gradient_mean': float(hf_mean),
                'gradient_std': float(hf_std),
                'gradient_max': float(hf_max),
                'high_freq_ratio': float(np.sum(gradient_magnitude > hf_mean + hf_std) / total_pixels)
            }
            
        except Exception:
            return {
                'gradient_mean': 0.0,
                'gradient_std': 0.0,
                'gradient_max': 0.0,
                'high_freq_ratio': 0.0
            }
    
    def _estimate_hidden_data_size(self, height: int, width: int, anomaly_score: float) -> int:
        """Estimate size of data hidden using DWT methods"""
        try:
            total_pixels = height * width
            
            # DWT steganography typically hides data in detail coefficients
            # Estimate based on anomaly score and typical hiding capacity
            detail_pixels = total_pixels * 0.75  # Approximately 75% are detail coefficients
            capacity_per_pixel = 0.5 * anomaly_score  # Variable capacity based on anomaly
            
            estimated_bits = int(detail_pixels * capacity_per_pixel)
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
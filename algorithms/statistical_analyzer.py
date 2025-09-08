"""
Statistical Analysis Algorithm
Detects steganography using statistical tests and image quality metrics
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math
from scipy import ndimage
from skimage.filters import sobel

class StatisticalAnalyzer:
    """Statistical steganography detection using multiple statistical tests"""
    
    def __init__(self):
        self.noise_threshold = 0.15
        self.symmetry_threshold = 0.3
        self.regularity_threshold = 25.0
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform statistical analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Perform multiple statistical tests
                tests_results = []
                suspicious_indicators = 0
                
                # Test 1: Noise analysis
                noise_score = self._analyze_noise_patterns(img_array)
                noise_suspicious = noise_score > self.noise_threshold
                if noise_suspicious:
                    suspicious_indicators += 1
                
                tests_results.append({
                    'test': 'Noise Pattern Analysis',
                    'score': noise_score,
                    'threshold': self.noise_threshold,
                    'suspicious': noise_suspicious
                })
                
                # Test 2: Histogram symmetry
                symmetry_score = self._analyze_histogram_symmetry(img_array)
                symmetry_suspicious = symmetry_score > self.symmetry_threshold
                if symmetry_suspicious:
                    suspicious_indicators += 1
                
                tests_results.append({
                    'test': 'Histogram Symmetry',
                    'score': symmetry_score,
                    'threshold': self.symmetry_threshold,
                    'suspicious': symmetry_suspicious
                })
                
                # Test 3: Image regularity
                regularity_score = self._analyze_image_regularity(img_array)
                regularity_suspicious = regularity_score > self.regularity_threshold
                if regularity_suspicious:
                    suspicious_indicators += 1
                
                tests_results.append({
                    'test': 'Image Regularity',
                    'score': regularity_score,
                    'threshold': self.regularity_threshold,
                    'suspicious': regularity_suspicious
                })
                
                # Test 4: Pixel correlation analysis
                correlation_score = self._analyze_pixel_correlation(img_array)
                correlation_suspicious = correlation_score < 0.7  # Low correlation is suspicious
                if correlation_suspicious:
                    suspicious_indicators += 1
                
                tests_results.append({
                    'test': 'Pixel Correlation',
                    'score': correlation_score,
                    'threshold': 0.7,
                    'suspicious': correlation_suspicious
                })
                
                # Test 5: Edge detection analysis
                edge_score = self._analyze_edge_patterns(img_array)
                edge_suspicious = edge_score > 0.25
                if edge_suspicious:
                    suspicious_indicators += 1
                
                tests_results.append({
                    'test': 'Edge Pattern Analysis',
                    'score': edge_score,
                    'threshold': 0.25,
                    'suspicious': edge_suspicious
                })
                
                # Calculate overall confidence
                total_tests = len(tests_results)
                confidence = min(95.0, (suspicious_indicators / total_tests) * 100.0)
                
                # Generate verdict
                if suspicious_indicators >= 3:
                    status = 'found'
                    message = f'Statistical anomalies detected in {suspicious_indicators}/{total_tests} tests'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(img_array, suspicious_indicators)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_tests': suspicious_indicators,
                            'total_tests': total_tests
                        },
                        'details': tests_results
                    }
                
                elif suspicious_indicators >= 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak statistical signals in {suspicious_indicators}/{total_tests} tests',
                        'details': tests_results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No statistical anomalies detected',
                        'details': tests_results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Statistical analysis failed: {str(e)}'
            }
    
    def _analyze_noise_patterns(self, img_array: np.ndarray) -> float:
        """Analyze noise patterns that might indicate steganography"""
        try:
            # Convert to grayscale for noise analysis
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array
            
            # Apply Gaussian filter to get smooth version
            smooth = ndimage.gaussian_filter(gray, sigma=1.0)
            
            # Calculate noise as difference between original and smooth
            noise = np.abs(gray - smooth)
            
            # Calculate noise statistics
            noise_std = np.std(noise)
            noise_mean = np.mean(noise)
            
            # High noise with low variance indicates regular noise patterns (suspicious)
            if noise_mean > 0:
                noise_regularity = noise_std / noise_mean
            else:
                noise_regularity = 0
            
            # Low regularity (high noise_std relative to mean) is suspicious
            if noise_regularity < 1.5:
                return min(1.0, (1.5 - noise_regularity) / 1.5)
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _analyze_histogram_symmetry(self, img_array: np.ndarray) -> float:
        """Analyze histogram for asymmetric patterns"""
        try:
            total_asymmetry = 0.0
            channels = img_array.shape[2] if len(img_array.shape) == 3 else 1
            
            for c in range(channels):
                if channels > 1:
                    channel_data = img_array[:, :, c]
                else:
                    channel_data = img_array
                
                # Calculate histogram
                hist, _ = np.histogram(channel_data.flatten(), bins=256, range=(0, 256))
                
                # Calculate asymmetry by comparing left and right halves
                left_half = hist[:128]
                right_half = hist[128:][::-1]  # Reverse for symmetry check
                
                # Pad shorter half if necessary
                min_len = min(len(left_half), len(right_half))
                left_half = left_half[:min_len]
                right_half = right_half[:min_len]
                
                # Calculate asymmetry score
                if np.sum(left_half) + np.sum(right_half) > 0:
                    diff = np.abs(left_half - right_half)
                    asymmetry = np.sum(diff) / (np.sum(left_half) + np.sum(right_half))
                    total_asymmetry += asymmetry
            
            return total_asymmetry / channels if channels > 0 else 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_image_regularity(self, img_array: np.ndarray) -> float:
        """Analyze image for artificial regularity patterns"""
        try:
            # Convert to grayscale
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array
            
            # Calculate local standard deviations using sliding window
            height, width = gray.shape
            window_size = 8
            local_stds = []
            
            for y in range(0, height - window_size + 1, window_size):
                for x in range(0, width - window_size + 1, window_size):
                    window = gray[y:y+window_size, x:x+window_size]
                    local_stds.append(np.std(window))
            
            if not local_stds:
                return 0.0
            
            # Calculate regularity - very uniform local variations are suspicious
            std_of_stds = np.std(local_stds)
            mean_of_stds = np.mean(local_stds)
            
            if mean_of_stds > 0:
                regularity_score = (1.0 - (std_of_stds / mean_of_stds)) * 100
                return max(0.0, regularity_score)
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _analyze_pixel_correlation(self, img_array: np.ndarray) -> float:
        """Analyze correlation between adjacent pixels"""
        try:
            if len(img_array.shape) == 3:
                # Average correlation across all channels
                total_correlation = 0.0
                channels = img_array.shape[2]
                
                for c in range(channels):
                    channel_data = img_array[:, :, c].flatten()
                    
                    # Calculate correlation with horizontally adjacent pixels
                    h_pixels = img_array[:, :-1, c].flatten()
                    h_adjacent = img_array[:, 1:, c].flatten()
                    
                    if len(h_pixels) > 1 and len(h_adjacent) > 1:
                        h_corr = np.corrcoef(h_pixels, h_adjacent)[0, 1]
                        if not np.isnan(h_corr):
                            total_correlation += abs(h_corr)
                
                return total_correlation / channels if channels > 0 else 0.0
                
            else:
                # Single channel
                h_pixels = img_array[:, :-1].flatten()
                h_adjacent = img_array[:, 1:].flatten()
                
                if len(h_pixels) > 1 and len(h_adjacent) > 1:
                    corr = np.corrcoef(h_pixels, h_adjacent)[0, 1]
                    return abs(corr) if not np.isnan(corr) else 0.0
                else:
                    return 0.0
                    
        except Exception:
            return 0.0
    
    def _analyze_edge_patterns(self, img_array: np.ndarray) -> float:
        """Analyze edge patterns for artificial regularities"""
        try:
            # Convert to grayscale
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array
            
            # Apply edge detection
            edges = sobel(gray / 255.0)  # Normalize to 0-1 range
            
            # Calculate edge statistics
            edge_mean = np.mean(edges)
            edge_std = np.std(edges)
            
            # Very uniform edge distribution can indicate steganography
            if edge_mean > 0:
                edge_regularity = edge_std / edge_mean
                # Low regularity (uniform edges) is suspicious
                return max(0.0, (1.0 - min(1.0, edge_regularity / 2.0)))
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, img_array: np.ndarray, suspicious_indicators: int) -> int:
        """Estimate hidden data size based on statistical anomalies"""
        try:
            height, width = img_array.shape[:2]
            total_pixels = height * width
            
            # Conservative estimate based on suspicious indicators
            capacity_ratio = suspicious_indicators / 10.0  # 10% per indicator
            estimated_bits = int(total_pixels * capacity_ratio)
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
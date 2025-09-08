"""
Alpha Channel Analysis Algorithm
Detects steganography hidden in the alpha (transparency) channel of images
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, Optional
import math

class AlphaAnalyzer:
    """Alpha channel steganography detection algorithm"""
    
    def __init__(self):
        self.entropy_threshold = 7.5
        self.pattern_threshold = 0.3
        self.transparency_variance_threshold = 50.0
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform alpha channel analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Check if image has alpha channel
                if img.mode not in ['RGBA', 'LA', 'PA']:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No alpha channel present in image'
                    }
                
                # Convert to RGBA if necessary
                if img.mode != 'RGBA':
                    img = img.convert('RGBA')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Extract alpha channel (4th channel in RGBA)
                if channels < 4:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'Alpha channel extraction failed'
                    }
                
                alpha_channel = img_array[:, :, 3]
                
                # Perform multiple alpha channel tests
                test_results = []
                suspicious_indicators = 0
                
                # Test 1: Alpha entropy analysis
                alpha_entropy = self._calculate_entropy(alpha_channel)
                entropy_suspicious = alpha_entropy > self.entropy_threshold
                if entropy_suspicious:
                    suspicious_indicators += 1
                
                test_results.append({
                    'test': 'Alpha Entropy',
                    'value': alpha_entropy,
                    'threshold': self.entropy_threshold,
                    'suspicious': entropy_suspicious
                })
                
                # Test 2: Transparency pattern analysis
                pattern_score = self._analyze_transparency_patterns(alpha_channel)
                pattern_suspicious = pattern_score > self.pattern_threshold
                if pattern_suspicious:
                    suspicious_indicators += 1
                
                test_results.append({
                    'test': 'Transparency Patterns',
                    'value': pattern_score,
                    'threshold': self.pattern_threshold,
                    'suspicious': pattern_suspicious
                })
                
                # Test 3: Alpha variance analysis
                alpha_variance = self._calculate_alpha_variance(alpha_channel)
                variance_suspicious = alpha_variance > self.transparency_variance_threshold
                if variance_suspicious:
                    suspicious_indicators += 1
                
                test_results.append({
                    'test': 'Alpha Variance',
                    'value': alpha_variance,
                    'threshold': self.transparency_variance_threshold,
                    'suspicious': variance_suspicious
                })
                
                # Test 4: LSB analysis on alpha channel
                alpha_lsb_score = self._analyze_alpha_lsb(alpha_channel)
                lsb_suspicious = alpha_lsb_score > 0.4
                if lsb_suspicious:
                    suspicious_indicators += 1
                
                test_results.append({
                    'test': 'Alpha LSB Analysis',
                    'value': alpha_lsb_score,
                    'threshold': 0.4,
                    'suspicious': lsb_suspicious
                })
                
                # Test 5: Alpha histogram analysis
                histogram_anomaly = self._analyze_alpha_histogram(alpha_channel)
                histogram_suspicious = histogram_anomaly > 0.25
                if histogram_suspicious:
                    suspicious_indicators += 1
                
                test_results.append({
                    'test': 'Alpha Histogram Anomaly',
                    'value': histogram_anomaly,
                    'threshold': 0.25,
                    'suspicious': histogram_suspicious
                })
                
                # Calculate confidence
                total_tests = len(test_results)
                confidence = min(95.0, (suspicious_indicators / total_tests) * 100.0)
                
                # Generate verdict
                if suspicious_indicators >= 3:
                    status = 'found'
                    message = f'Alpha channel steganography detected in {suspicious_indicators}/{total_tests} tests'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(alpha_channel)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'alpha_entropy': alpha_entropy,
                            'suspicious_tests': suspicious_indicators
                        },
                        'details': test_results
                    }
                
                elif suspicious_indicators >= 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak alpha channel signals in {suspicious_indicators}/{total_tests} tests',
                        'details': test_results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No alpha channel steganography detected',
                        'details': test_results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Alpha channel analysis failed: {str(e)}'
            }
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy of alpha channel data"""
        try:
            # Get unique values and their counts
            unique_values, counts = np.unique(data.flatten(), return_counts=True)
            
            # Calculate probabilities
            total = len(data.flatten())
            probabilities = counts / total
            
            # Calculate entropy
            entropy = 0.0
            for p in probabilities:
                if p > 0:
                    entropy -= p * math.log2(p)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _analyze_transparency_patterns(self, alpha_channel: np.ndarray) -> float:
        """Analyze patterns in transparency values"""
        try:
            height, width = alpha_channel.shape
            
            # Look for artificial patterns in alpha values
            # Calculate local variations
            variations = []
            
            window_size = 4
            for y in range(0, height - window_size + 1, window_size):
                for x in range(0, width - window_size + 1, window_size):
                    window = alpha_channel[y:y+window_size, x:x+window_size]
                    window_std = np.std(window)
                    variations.append(window_std)
            
            if not variations:
                return 0.0
            
            # Calculate regularity of variations
            variations_array = np.array(variations)
            std_of_variations = np.std(variations_array)
            mean_of_variations = np.mean(variations_array)
            
            if mean_of_variations > 0:
                # High regularity (low std relative to mean) is suspicious
                regularity = 1.0 - min(1.0, std_of_variations / mean_of_variations)
                return regularity
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _calculate_alpha_variance(self, alpha_channel: np.ndarray) -> float:
        """Calculate variance in alpha channel values"""
        try:
            return float(np.var(alpha_channel))
        except Exception:
            return 0.0
    
    def _analyze_alpha_lsb(self, alpha_channel: np.ndarray) -> float:
        """Analyze LSBs of alpha channel for hidden data"""
        try:
            # Extract LSBs
            lsb_data = alpha_channel & 1
            
            # Calculate LSB entropy
            lsb_entropy = self._calculate_entropy(lsb_data)
            
            # High entropy in LSBs is suspicious for alpha channel
            # (alpha channels typically have lower entropy than RGB channels)
            max_lsb_entropy = 1.0  # Max entropy for binary data
            
            if max_lsb_entropy > 0:
                return lsb_entropy / max_lsb_entropy
            else:
                return 0.0
                
        except Exception:
            return 0.0
    
    def _analyze_alpha_histogram(self, alpha_channel: np.ndarray) -> float:
        """Analyze alpha channel histogram for anomalies"""
        try:
            # Calculate histogram
            hist, _ = np.histogram(alpha_channel.flatten(), bins=256, range=(0, 256))
            
            # Common alpha values are 0 (transparent) and 255 (opaque)
            # Look for unusual distributions
            
            transparent_count = hist[0]  # Fully transparent pixels
            opaque_count = hist[255]    # Fully opaque pixels
            total_pixels = alpha_channel.size
            
            # Calculate percentage of transparent and opaque pixels
            transparent_ratio = transparent_count / total_pixels
            opaque_ratio = opaque_count / total_pixels
            
            # If most pixels are neither fully transparent nor fully opaque,
            # and there's a lot of intermediate values, it might be suspicious
            intermediate_ratio = 1.0 - transparent_ratio - opaque_ratio
            
            # High intermediate ratio with uniform distribution is suspicious
            if intermediate_ratio > 0.5:
                # Check distribution of intermediate values
                intermediate_hist = hist[1:255]
                if len(intermediate_hist) > 0:
                    intermediate_std = np.std(intermediate_hist)
                    intermediate_mean = np.mean(intermediate_hist)
                    
                    if intermediate_mean > 0:
                        # Low variation in intermediate values is suspicious
                        variation = intermediate_std / intermediate_mean
                        return max(0.0, 1.0 - variation)
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, alpha_channel: np.ndarray) -> int:
        """Estimate size of data hidden in alpha channel"""
        try:
            height, width = alpha_channel.shape
            total_pixels = height * width
            
            # Conservative estimate: assume 1-2 bits per pixel can be hidden
            estimated_bits = total_pixels * 1.5  # 1.5 bits per pixel average
            estimated_bytes = max(1, int(estimated_bits // 8))
            
            return estimated_bytes
            
        except Exception:
            return 1
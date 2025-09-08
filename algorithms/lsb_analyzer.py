"""
LSB (Least Significant Bit) Analysis Algorithm
Detects hidden data in the least significant bits of image pixels
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, Optional, Tuple
import math

class LSBAnalyzer:
    """LSB steganography detection algorithm"""
    
    def __init__(self):
        self.threshold_chi_square = 20.0  # Chi-square test threshold
        self.threshold_entropy = 7.9      # Entropy threshold
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform LSB analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Convert to numpy array
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Analyze each color channel
                results = []
                total_bits_analyzed = 0
                suspicious_patterns = 0
                
                for channel in range(channels):
                    channel_data = img_array[:, :, channel]
                    
                    # Extract LSBs
                    lsb_data = self._extract_lsb_plane(channel_data)
                    
                    # Perform statistical tests
                    chi_square = self._chi_square_test(lsb_data)
                    entropy = self._calculate_entropy(lsb_data)
                    
                    # Check for patterns
                    pattern_score = self._detect_patterns(lsb_data)
                    
                    channel_name = ['Red', 'Green', 'Blue'][channel]
                    results.append({
                        'channel': channel_name,
                        'chi_square': chi_square,
                        'entropy': entropy,
                        'pattern_score': pattern_score,
                        'suspicious': chi_square > self.threshold_chi_square or entropy > self.threshold_entropy
                    })
                    
                    if chi_square > self.threshold_chi_square or entropy > self.threshold_entropy:
                        suspicious_patterns += 1
                    
                    total_bits_analyzed += lsb_data.size
                
                # Generate final verdict
                confidence = min(95.0, (suspicious_patterns / channels) * 100.0)
                
                if suspicious_patterns >= 2:
                    status = 'found'
                    message = f'LSB steganography detected in {suspicious_patterns} channels'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(img_array)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'channels_affected': suspicious_patterns,
                            'total_bits_analyzed': total_bits_analyzed
                        },
                        'details': results
                    }
                
                elif suspicious_patterns == 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak LSB signal detected in {results[0]["channel"] if suspicious_patterns == 1 else "multiple"} channel(s)',
                        'details': results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No LSB steganography detected',
                        'details': results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'LSB analysis failed: {str(e)}'
            }
    
    def _extract_lsb_plane(self, channel_data: np.ndarray) -> np.ndarray:
        """Extract the least significant bit plane from a channel"""
        return channel_data & 1
    
    def _chi_square_test(self, lsb_data: np.ndarray) -> float:
        """Perform chi-square test on LSB data"""
        try:
            # Count occurrences of 0s and 1s
            unique, counts = np.unique(lsb_data, return_counts=True)
            
            if len(counts) < 2:
                return 0.0
            
            # Expected frequency (should be roughly equal for random data)
            total = np.sum(counts)
            expected = total / 2.0
            
            # Chi-square statistic
            chi_square = 0.0
            for count in counts:
                chi_square += ((count - expected) ** 2) / expected
            
            return chi_square
            
        except Exception:
            return 0.0
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy of the data"""
        try:
            # Get unique values and their counts
            _, counts = np.unique(data, return_counts=True)
            
            # Calculate probabilities
            total = len(data)
            probabilities = counts / total
            
            # Calculate entropy
            entropy = 0.0
            for p in probabilities:
                if p > 0:
                    entropy -= p * math.log2(p)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _detect_patterns(self, lsb_data: np.ndarray) -> float:
        """Detect non-random patterns in LSB data"""
        try:
            # Flatten the data
            flat_data = lsb_data.flatten()
            
            # Check for runs (consecutive same bits)
            runs = []
            current_run = 1
            
            for i in range(1, len(flat_data)):
                if flat_data[i] == flat_data[i-1]:
                    current_run += 1
                else:
                    runs.append(current_run)
                    current_run = 1
            runs.append(current_run)
            
            # Calculate run statistics
            avg_run_length = np.mean(runs)
            max_run_length = np.max(runs)
            
            # Pattern score (higher = more suspicious)
            pattern_score = 0.0
            
            # Long runs are suspicious
            if max_run_length > 20:
                pattern_score += min(50.0, max_run_length)
            
            # Very short or very long average runs are suspicious
            if avg_run_length < 1.8 or avg_run_length > 2.2:
                pattern_score += abs(avg_run_length - 2.0) * 10
            
            return min(100.0, pattern_score)
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, img_array: np.ndarray) -> int:
        """Estimate the size of hidden data in bytes"""
        try:
            height, width, channels = img_array.shape
            
            # Each pixel can hide up to 3 bits (1 per channel for RGB)
            max_bits = height * width * channels
            
            # Estimate based on suspicious patterns (conservative estimate)
            estimated_bits = max_bits // 8  # Assume 1/8 of available space is used
            estimated_bytes = estimated_bits // 8
            
            return max(1, estimated_bytes)
            
        except Exception:
            return 0
"""
Histogram Analysis Algorithm
Detects steganography using histogram-based methods and histogram shifting detection
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

class HistogramAnalyzer:
    """Histogram-based steganography detection algorithm"""
    
    def __init__(self):
        self.shift_threshold = 0.4      # Threshold for histogram shifting detection
        self.anomaly_threshold = 0.35   # Threshold for general histogram anomalies
        self.peak_threshold = 0.15      # Threshold for unusual peak detection
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform histogram analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Analyze each color channel
                channel_results = []
                total_anomaly_score = 0.0
                suspicious_channels = 0
                shift_indicators = 0
                
                for channel_idx in range(channels):
                    channel_data = img_array[:, :, channel_idx]
                    channel_name = ['Red', 'Green', 'Blue'][channel_idx]
                    
                    # Calculate histogram
                    histogram = self._calculate_histogram(channel_data)
                    
                    # Perform multiple histogram tests
                    shift_score = self._detect_histogram_shifting(histogram)
                    peak_anomaly = self._detect_peak_anomalies(histogram)
                    distribution_anomaly = self._analyze_distribution_anomalies(histogram)
                    smoothness_anomaly = self._analyze_histogram_smoothness(histogram)
                    
                    # Calculate overall channel anomaly score
                    channel_anomaly = (shift_score * 0.4 + 
                                     peak_anomaly * 0.3 + 
                                     distribution_anomaly * 0.2 + 
                                     smoothness_anomaly * 0.1)
                    
                    is_suspicious = channel_anomaly > self.anomaly_threshold
                    if is_suspicious:
                        suspicious_channels += 1
                    
                    # Count shift indicators
                    if shift_score > self.shift_threshold:
                        shift_indicators += 1
                    
                    total_anomaly_score += channel_anomaly
                    
                    channel_results.append({
                        'channel': channel_name,
                        'anomaly_score': channel_anomaly,
                        'shift_score': shift_score,
                        'peak_anomaly': peak_anomaly,
                        'distribution_anomaly': distribution_anomaly,
                        'smoothness_anomaly': smoothness_anomaly,
                        'is_suspicious': is_suspicious
                    })
                
                # Calculate overall confidence
                avg_anomaly_score = total_anomaly_score / channels if channels > 0 else 0.0
                confidence = min(95.0, avg_anomaly_score * 200)  # Scale to percentage
                
                # Additional cross-channel analysis
                cross_channel_anomaly = self._analyze_cross_channel_correlation(img_array)
                
                # Generate verdict
                if suspicious_channels >= 2 or shift_indicators >= 2:
                    status = 'found'
                    if shift_indicators >= 2:
                        message = f'Histogram shifting detected in {shift_indicators} channels'
                    else:
                        message = f'Histogram anomalies detected in {suspicious_channels} channels'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(height, width, avg_anomaly_score)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_channels': suspicious_channels,
                            'shift_indicators': shift_indicators,
                            'avg_anomaly_score': round(avg_anomaly_score, 3)
                        },
                        'details': channel_results
                    }
                
                elif suspicious_channels == 1 or shift_indicators == 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak histogram signals detected',
                        'details': channel_results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No histogram-based steganography detected',
                        'details': channel_results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Histogram analysis failed: {str(e)}'
            }
    
    def _calculate_histogram(self, channel_data: np.ndarray) -> np.ndarray:
        """Calculate histogram for a single channel"""
        try:
            hist, _ = np.histogram(channel_data.flatten(), bins=256, range=(0, 256))
            return hist
        except Exception:
            return np.zeros(256)
    
    def _detect_histogram_shifting(self, histogram: np.ndarray) -> float:
        """Detect histogram shifting steganography"""
        try:
            shift_score = 0.0
            
            # Look for characteristic patterns of histogram shifting
            # 1. Unusual gaps in histogram (shifted values)
            gap_score = self._detect_histogram_gaps(histogram)
            shift_score += gap_score * 0.5
            
            # 2. Artificial peaks at specific values
            peak_shift_score = self._detect_shift_peaks(histogram)
            shift_score += peak_shift_score * 0.3
            
            # 3. Asymmetric distribution around peaks
            asymmetry_score = self._detect_peak_asymmetry(histogram)
            shift_score += asymmetry_score * 0.2
            
            return min(1.0, shift_score)
            
        except Exception:
            return 0.0
    
    def _detect_histogram_gaps(self, histogram: np.ndarray) -> float:
        """Detect unusual gaps that indicate histogram shifting"""
        try:
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            gap_score = 0.0
            consecutive_zeros = 0
            max_consecutive_zeros = 0
            
            # Find consecutive zero bins
            for i in range(len(histogram)):
                if histogram[i] == 0:
                    consecutive_zeros += 1
                    max_consecutive_zeros = max(max_consecutive_zeros, consecutive_zeros)
                else:
                    consecutive_zeros = 0
            
            # Long consecutive gaps are suspicious
            if max_consecutive_zeros > 3:
                gap_score += min(0.5, (max_consecutive_zeros - 3) / 10.0)
            
            # Check for gaps around common values (128, 64, 192, etc.)
            suspicious_regions = [64, 128, 192]
            for center in suspicious_regions:
                if center - 2 >= 0 and center + 2 < len(histogram):
                    window = histogram[center-2:center+3]
                    zero_count = np.sum(window == 0)
                    if zero_count >= 3:  # 3 or more zeros in 5-bin window
                        gap_score += 0.1
            
            return min(1.0, gap_score)
            
        except Exception:
            return 0.0
    
    def _detect_shift_peaks(self, histogram: np.ndarray) -> float:
        """Detect artificial peaks created by histogram shifting"""
        try:
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            peak_score = 0.0
            
            # Find local maxima
            peaks = []
            for i in range(1, len(histogram) - 1):
                if histogram[i] > histogram[i-1] and histogram[i] > histogram[i+1]:
                    if histogram[i] > total_pixels * 0.001:  # At least 0.1% of pixels
                        peaks.append((i, histogram[i]))
            
            if not peaks:
                return 0.0
            
            # Check for artificial peak patterns
            for value, count in peaks:
                peak_ratio = count / total_pixels
                
                # Very sharp peaks are suspicious
                if peak_ratio > self.peak_threshold:
                    # Check peak sharpness
                    left_neighbor = histogram[value-1] if value > 0 else 0
                    right_neighbor = histogram[value+1] if value < len(histogram)-1 else 0
                    
                    avg_neighbor = (left_neighbor + right_neighbor) / 2
                    if avg_neighbor > 0:
                        sharpness = count / avg_neighbor
                        if sharpness > 3.0:  # Peak is 3x higher than neighbors
                            peak_score += min(0.3, (sharpness - 3.0) / 10.0)
            
            return min(1.0, peak_score)
            
        except Exception:
            return 0.0
    
    def _detect_peak_asymmetry(self, histogram: np.ndarray) -> float:
        """Detect asymmetric patterns around histogram peaks"""
        try:
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            asymmetry_score = 0.0
            
            # Find significant peaks
            for i in range(2, len(histogram) - 2):
                if histogram[i] > total_pixels * 0.01:  # At least 1% of pixels
                    # Check asymmetry around this peak
                    left_sum = histogram[i-2] + histogram[i-1]
                    right_sum = histogram[i+1] + histogram[i+2]
                    
                    if left_sum + right_sum > 0:
                        asymmetry = abs(left_sum - right_sum) / (left_sum + right_sum)
                        if asymmetry > 0.6:  # Highly asymmetric
                            asymmetry_score += min(0.2, (asymmetry - 0.6) / 2.0)
            
            return min(1.0, asymmetry_score)
            
        except Exception:
            return 0.0
    
    def _detect_peak_anomalies(self, histogram: np.ndarray) -> float:
        """Detect unusual peak patterns in histogram"""
        try:
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            anomaly_score = 0.0
            
            # Check for too many significant peaks
            significant_peaks = 0
            for count in histogram:
                if count > total_pixels * 0.02:  # More than 2% of pixels
                    significant_peaks += 1
            
            if significant_peaks > 10:  # Too many peaks
                anomaly_score += min(0.3, (significant_peaks - 10) / 20.0)
            
            # Check for uniform distribution (too flat)
            non_zero_bins = np.sum(histogram > 0)
            if non_zero_bins > 0:
                histogram_entropy = self._calculate_entropy(histogram)
                max_entropy = math.log2(non_zero_bins)
                
                if max_entropy > 0:
                    normalized_entropy = histogram_entropy / max_entropy
                    # Very high entropy (uniform) can be suspicious
                    if normalized_entropy > 0.95:
                        anomaly_score += (normalized_entropy - 0.95) * 2
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_distribution_anomalies(self, histogram: np.ndarray) -> float:
        """Analyze histogram distribution for anomalies"""
        try:
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            anomaly_score = 0.0
            
            # Check for unusual concentration at boundaries (0 and 255)
            boundary_pixels = histogram[0] + histogram[255]
            boundary_ratio = boundary_pixels / total_pixels
            
            if boundary_ratio < 0.01:  # Less than 1% at boundaries (suspicious)
                anomaly_score += (0.01 - boundary_ratio) * 10
            elif boundary_ratio > 0.3:  # More than 30% at boundaries
                anomaly_score += (boundary_ratio - 0.3) * 0.5
            
            # Check for unusual mid-range concentration
            mid_range = histogram[64:192]  # Middle 128 values
            mid_ratio = np.sum(mid_range) / total_pixels
            
            if mid_ratio > 0.8:  # More than 80% in mid-range
                anomaly_score += (mid_ratio - 0.8) * 0.5
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_histogram_smoothness(self, histogram: np.ndarray) -> float:
        """Analyze histogram smoothness for artificial patterns"""
        try:
            if len(histogram) < 3:
                return 0.0
            
            # Calculate second derivative (measure of smoothness)
            second_derivative = []
            for i in range(1, len(histogram) - 1):
                second_deriv = histogram[i-1] - 2*histogram[i] + histogram[i+1]
                second_derivative.append(abs(second_deriv))
            
            if not second_derivative:
                return 0.0
            
            # High second derivative indicates jaggedness
            avg_second_deriv = np.mean(second_derivative)
            max_second_deriv = np.max(second_derivative)
            
            total_pixels = np.sum(histogram)
            if total_pixels == 0:
                return 0.0
            
            # Normalize by total pixels
            normalized_avg = avg_second_deriv / total_pixels
            normalized_max = max_second_deriv / total_pixels
            
            # Very jagged histograms can indicate steganography
            anomaly_score = 0.0
            if normalized_avg > 0.01:  # 1% of total pixels
                anomaly_score += min(0.3, (normalized_avg - 0.01) * 30)
            
            if normalized_max > 0.05:  # 5% of total pixels
                anomaly_score += min(0.2, (normalized_max - 0.05) * 4)
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _calculate_entropy(self, histogram: np.ndarray) -> float:
        """Calculate Shannon entropy of histogram"""
        try:
            total = np.sum(histogram)
            if total == 0:
                return 0.0
            
            entropy = 0.0
            for count in histogram:
                if count > 0:
                    probability = count / total
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _analyze_cross_channel_correlation(self, img_array: np.ndarray) -> float:
        """Analyze correlation between color channels"""
        try:
            if len(img_array.shape) != 3 or img_array.shape[2] < 3:
                return 0.0
            
            height, width, channels = img_array.shape
            
            # Calculate histograms for all channels
            histograms = []
            for c in range(channels):
                hist = self._calculate_histogram(img_array[:, :, c])
                histograms.append(hist)
            
            # Calculate cross-correlations
            correlations = []
            for i in range(channels):
                for j in range(i+1, channels):
                    corr = np.corrcoef(histograms[i], histograms[j])[0, 1]
                    if not np.isnan(corr):
                        correlations.append(abs(corr))
            
            if not correlations:
                return 0.0
            
            # Very high or very low correlations can be suspicious
            avg_correlation = np.mean(correlations)
            
            anomaly_score = 0.0
            if avg_correlation > 0.95:  # Too similar
                anomaly_score += (avg_correlation - 0.95) * 4
            elif avg_correlation < 0.3:  # Too different
                anomaly_score += (0.3 - avg_correlation) * 2
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, height: int, width: int, anomaly_score: float) -> int:
        """Estimate size of data hidden using histogram methods"""
        try:
            total_pixels = height * width
            
            # Histogram shifting can hide 1 bit per pixel in affected regions
            # Conservative estimate based on anomaly score
            affected_ratio = anomaly_score * 0.5  # Up to 50% of pixels affected
            estimated_bits = int(total_pixels * affected_ratio)
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
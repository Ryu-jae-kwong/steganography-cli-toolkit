"""
PVD (Pixel Value Differencing) Analysis Algorithm
Detects steganography based on pixel value differences and edge detection
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

class PVDAnalyzer:
    """PVD steganography detection algorithm"""
    
    def __init__(self):
        self.smooth_threshold = 8    # Threshold for smooth regions
        self.edge_threshold = 24     # Threshold for edge regions
        self.anomaly_threshold = 0.3  # Threshold for PVD anomaly detection
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform PVD analysis on image file"""
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
                
                for channel_idx in range(channels):
                    channel_data = img_array[:, :, channel_idx]
                    channel_name = ['Red', 'Green', 'Blue'][channel_idx]
                    
                    # Perform PVD analysis on this channel
                    anomaly_score = self._analyze_channel_pvd(channel_data)
                    
                    is_suspicious = anomaly_score > self.anomaly_threshold
                    if is_suspicious:
                        suspicious_channels += 1
                    
                    total_anomaly_score += anomaly_score
                    
                    # Detailed analysis for this channel
                    smooth_regions, edge_regions = self._classify_regions(channel_data)
                    histogram_analysis = self._analyze_difference_histogram(channel_data)
                    
                    channel_results.append({
                        'channel': channel_name,
                        'anomaly_score': anomaly_score,
                        'is_suspicious': is_suspicious,
                        'smooth_regions': smooth_regions,
                        'edge_regions': edge_regions,
                        'histogram_anomaly': histogram_analysis
                    })
                
                # Calculate overall confidence
                avg_anomaly_score = total_anomaly_score / channels if channels > 0 else 0.0
                confidence = min(95.0, avg_anomaly_score * 200)  # Scale to percentage
                
                # Generate verdict
                if suspicious_channels >= 2:
                    status = 'found'
                    message = f'PVD steganography detected in {suspicious_channels} channels'
                    
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
                            'avg_anomaly_score': round(avg_anomaly_score, 3)
                        },
                        'details': channel_results
                    }
                
                elif suspicious_channels == 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak PVD signals in {suspicious_channels} channel',
                        'details': channel_results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No PVD steganography detected',
                        'details': channel_results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'PVD analysis failed: {str(e)}'
            }
    
    def _analyze_channel_pvd(self, channel_data: np.ndarray) -> float:
        """Analyze a single channel for PVD anomalies"""
        try:
            height, width = channel_data.shape
            
            # Calculate horizontal pixel differences
            h_diffs = []
            for y in range(height):
                for x in range(width - 1):
                    diff = abs(int(channel_data[y, x]) - int(channel_data[y, x + 1]))
                    h_diffs.append(diff)
            
            # Calculate vertical pixel differences
            v_diffs = []
            for y in range(height - 1):
                for x in range(width):
                    diff = abs(int(channel_data[y, x]) - int(channel_data[y + 1, x]))
                    v_diffs.append(diff)
            
            all_diffs = h_diffs + v_diffs
            
            if not all_diffs:
                return 0.0
            
            # Analyze difference distribution for PVD patterns
            anomaly_score = 0.0
            
            # Test 1: Unusual difference patterns
            diff_histogram = self._calculate_difference_histogram(all_diffs)
            histogram_anomaly = self._detect_histogram_anomalies(diff_histogram)
            anomaly_score += histogram_anomaly * 0.4
            
            # Test 2: Capacity region analysis
            capacity_anomaly = self._analyze_capacity_regions(all_diffs)
            anomaly_score += capacity_anomaly * 0.3
            
            # Test 3: Statistical distribution test
            statistical_anomaly = self._test_difference_statistics(all_diffs)
            anomaly_score += statistical_anomaly * 0.3
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _calculate_difference_histogram(self, differences: List[int]) -> np.ndarray:
        """Calculate histogram of pixel differences"""
        try:
            hist, _ = np.histogram(differences, bins=256, range=(0, 255))
            return hist
        except Exception:
            return np.zeros(256)
    
    def _detect_histogram_anomalies(self, histogram: np.ndarray) -> float:
        """Detect anomalies in difference histogram that indicate PVD"""
        try:
            # PVD creates characteristic patterns in difference histograms
            total_count = np.sum(histogram)
            if total_count == 0:
                return 0.0
            
            anomaly_score = 0.0
            
            # Check for unusual peaks in specific difference ranges
            # PVD typically affects differences in ranges [1-7], [8-15], [16-31], etc.
            ranges = [(1, 7), (8, 15), (16, 31), (32, 63)]
            
            for start, end in ranges:
                if end < len(histogram):
                    range_count = np.sum(histogram[start:end+1])
                    range_ratio = range_count / total_count
                    
                    # Unusual concentrations in these ranges are suspicious
                    if range_ratio > 0.15:  # More than 15% in any range
                        anomaly_score += (range_ratio - 0.15) * 2
            
            # Check for artificial regularities
            # Calculate variance in adjacent histogram bins
            if len(histogram) > 10:
                variances = []
                for i in range(10, min(50, len(histogram) - 1)):
                    if histogram[i] + histogram[i+1] > 0:
                        variance = abs(histogram[i] - histogram[i+1]) / max(1, histogram[i] + histogram[i+1])
                        variances.append(variance)
                
                if variances:
                    avg_variance = np.mean(variances)
                    # Very low variance indicates artificial regularity
                    if avg_variance < 0.3:
                        anomaly_score += (0.3 - avg_variance)
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_capacity_regions(self, differences: List[int]) -> float:
        """Analyze PVD capacity regions for anomalies"""
        try:
            # PVD divides differences into capacity regions
            # Each region can hide a specific number of bits
            
            region_counts = {
                'low_capacity': 0,    # 0-7: can hide 0-2 bits
                'medium_capacity': 0, # 8-31: can hide 3-4 bits  
                'high_capacity': 0    # 32+: can hide 5+ bits
            }
            
            for diff in differences:
                if diff <= 7:
                    region_counts['low_capacity'] += 1
                elif diff <= 31:
                    region_counts['medium_capacity'] += 1
                else:
                    region_counts['high_capacity'] += 1
            
            total_diffs = len(differences)
            if total_diffs == 0:
                return 0.0
            
            # Calculate ratios
            low_ratio = region_counts['low_capacity'] / total_diffs
            medium_ratio = region_counts['medium_capacity'] / total_diffs
            high_ratio = region_counts['high_capacity'] / total_diffs
            
            # Unusual distributions are suspicious
            anomaly_score = 0.0
            
            # Too many medium/high capacity regions might indicate steganography
            if medium_ratio > 0.4:  # More than 40% medium capacity
                anomaly_score += (medium_ratio - 0.4)
            
            if high_ratio > 0.2:    # More than 20% high capacity
                anomaly_score += (high_ratio - 0.2) * 2
            
            # Very uniform distribution is also suspicious
            entropy = 0.0
            for ratio in [low_ratio, medium_ratio, high_ratio]:
                if ratio > 0:
                    entropy -= ratio * math.log2(ratio)
            
            # Maximum entropy for 3 categories is log2(3) ≈ 1.585
            normalized_entropy = entropy / 1.585 if entropy > 0 else 0
            
            # Very high entropy (uniform distribution) can be suspicious
            if normalized_entropy > 0.95:
                anomaly_score += (normalized_entropy - 0.95) * 2
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _test_difference_statistics(self, differences: List[int]) -> float:
        """Test statistical properties of pixel differences"""
        try:
            if len(differences) < 10:
                return 0.0
            
            diff_array = np.array(differences)
            
            # Calculate statistical measures
            mean_diff = np.mean(diff_array)
            std_diff = np.std(diff_array)
            
            anomaly_score = 0.0
            
            # Test 1: Unusual mean difference
            # Natural images typically have mean difference around 8-15
            if mean_diff < 5 or mean_diff > 25:
                anomaly_score += min(0.3, abs(mean_diff - 12) / 40)
            
            # Test 2: Unusual standard deviation
            # Check if std deviation is unusually regular
            if std_diff > 0:
                cv = std_diff / mean_diff  # Coefficient of variation
                # Very low or very high CV can be suspicious
                if cv < 0.5 or cv > 3.0:
                    anomaly_score += min(0.3, abs(cv - 1.5) / 5)
            
            # Test 3: Distribution shape test
            # Check for unusual skewness in difference distribution
            sorted_diffs = np.sorted(diff_array)
            median_diff = np.median(sorted_diffs)
            
            if mean_diff > 0 and median_diff > 0:
                skewness_indicator = abs(mean_diff - median_diff) / mean_diff
                if skewness_indicator > 0.5:  # Highly skewed
                    anomaly_score += min(0.2, skewness_indicator - 0.5)
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _classify_regions(self, channel_data: np.ndarray) -> Tuple[int, int]:
        """Classify image regions as smooth or edge regions"""
        try:
            height, width = channel_data.shape
            smooth_count = 0
            edge_count = 0
            
            # Simple edge detection using local variance
            window_size = 3
            for y in range(window_size, height - window_size):
                for x in range(window_size, width - window_size):
                    window = channel_data[y-1:y+2, x-1:x+2]
                    local_variance = np.var(window)
                    
                    if local_variance < self.smooth_threshold:
                        smooth_count += 1
                    elif local_variance > self.edge_threshold:
                        edge_count += 1
            
            return smooth_count, edge_count
            
        except Exception:
            return 0, 0
    
    def _analyze_difference_histogram(self, channel_data: np.ndarray) -> Dict[str, float]:
        """Analyze difference histogram for additional insights"""
        try:
            height, width = channel_data.shape
            
            # Calculate all pixel differences
            all_diffs = []
            
            # Horizontal differences
            for y in range(height):
                for x in range(width - 1):
                    diff = abs(int(channel_data[y, x]) - int(channel_data[y, x + 1]))
                    all_diffs.append(diff)
            
            if not all_diffs:
                return {'entropy': 0.0, 'peak_ratio': 0.0}
            
            # Calculate histogram
            hist, _ = np.histogram(all_diffs, bins=32, range=(0, 32))
            
            # Calculate entropy
            total = sum(hist)
            entropy = 0.0
            if total > 0:
                for count in hist:
                    if count > 0:
                        prob = count / total
                        entropy -= prob * math.log2(prob)
            
            # Find peak ratio
            max_count = max(hist) if hist.size > 0 else 0
            peak_ratio = max_count / total if total > 0 else 0.0
            
            return {
                'entropy': entropy,
                'peak_ratio': peak_ratio
            }
            
        except Exception:
            return {'entropy': 0.0, 'peak_ratio': 0.0}
    
    def _estimate_hidden_data_size(self, height: int, width: int, anomaly_score: float) -> int:
        """Estimate size of data hidden using PVD"""
        try:
            total_pixels = height * width
            
            # PVD can hide variable bits per pixel pair depending on difference
            # Conservative estimate based on anomaly score
            avg_bits_per_pair = 2.5 * anomaly_score  # 0 to 2.5 bits per pair
            pixel_pairs = total_pixels // 2
            
            estimated_bits = int(pixel_pairs * avg_bits_per_pair)
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
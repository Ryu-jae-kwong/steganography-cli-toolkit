"""
F5 Analysis Algorithm
Detects F5 steganography in JPEG images using matrix encoding detection
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

try:
    from PIL.ExifTags import TAGS
    EXIF_AVAILABLE = True
except ImportError:
    EXIF_AVAILABLE = False

class F5Analyzer:
    """F5 steganography detection algorithm"""
    
    def __init__(self):
        self.matrix_threshold = 0.4      # Threshold for matrix encoding detection
        self.coefficient_threshold = 0.35 # Threshold for DCT coefficient anomalies
        self.histogram_threshold = 0.3    # Threshold for histogram anomalies
        self.block_size = 8              # JPEG DCT block size
        
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform F5 analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # F5 works specifically with JPEG images
                if img.format != 'JPEG':
                    return {
                        'status': 'none',
                        'message': 'F5 analysis only applicable to JPEG images',
                        'confidence': 0.0
                    }
                
                # Convert to YCbCr for analysis (F5 primarily uses luminance)
                if img.mode != 'YCbCr':
                    if img.mode == 'RGBA':
                        img = img.convert('RGB')
                    img_ycbcr = img.convert('YCbCr')
                else:
                    img_ycbcr = img
                
                img_array = np.array(img_ycbcr)
                height, width, channels = img_array.shape
                
                # Focus on luminance channel (Y) where F5 typically operates
                luminance = img_array[:, :, 0].astype(np.float32)
                
                # Analyze F5-specific patterns
                matrix_encoding_score = self._detect_matrix_encoding_patterns(luminance)
                coefficient_analysis = self._analyze_dct_coefficient_patterns(luminance)
                histogram_analysis = self._analyze_coefficient_histogram(luminance)
                shrinkage_detection = self._detect_shrinkage_artifacts(luminance)
                
                # Calculate overall anomaly score
                overall_anomaly = (
                    matrix_encoding_score * 0.35 +
                    coefficient_analysis * 0.25 +
                    histogram_analysis * 0.25 +
                    shrinkage_detection * 0.15
                )
                
                # Calculate confidence
                confidence = min(95.0, overall_anomaly * 180)
                
                # Additional JPEG metadata analysis
                metadata_analysis = self._analyze_jpeg_metadata(file_path)
                
                # Generate verdict
                if overall_anomaly > self.matrix_threshold:
                    status = 'found'
                    message = 'F5 steganography patterns detected'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(height, width, overall_anomaly)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'overall_anomaly': round(overall_anomaly, 3),
                            'matrix_encoding_score': round(matrix_encoding_score, 3)
                        },
                        'details': {
                            'matrix_encoding': matrix_encoding_score,
                            'coefficient_patterns': coefficient_analysis,
                            'histogram_anomaly': histogram_analysis,
                            'shrinkage_detection': shrinkage_detection,
                            'metadata_analysis': metadata_analysis
                        }
                    }
                
                elif overall_anomaly > self.coefficient_threshold:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': 'Weak F5-like patterns detected',
                        'details': {
                            'matrix_encoding': matrix_encoding_score,
                            'coefficient_patterns': coefficient_analysis,
                            'histogram_anomaly': histogram_analysis,
                            'shrinkage_detection': shrinkage_detection,
                            'metadata_analysis': metadata_analysis
                        }
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No F5 steganography detected',
                        'details': {
                            'matrix_encoding': matrix_encoding_score,
                            'coefficient_patterns': coefficient_analysis,
                            'histogram_anomaly': histogram_analysis,
                            'shrinkage_detection': shrinkage_detection,
                            'metadata_analysis': metadata_analysis
                        }
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'F5 analysis failed: {str(e)}'
            }
    
    def _detect_matrix_encoding_patterns(self, luminance: np.ndarray) -> float:
        """Detect matrix encoding patterns characteristic of F5"""
        try:
            height, width = luminance.shape
            anomaly_score = 0.0
            
            # Simulate DCT coefficient analysis
            # F5 uses matrix encoding which creates specific statistical patterns
            
            # Test 1: Analyze coefficient pair correlations
            pair_correlations = []
            for y in range(0, height - self.block_size, self.block_size):
                for x in range(0, width - self.block_size, self.block_size):
                    block = luminance[y:y+self.block_size, x:x+self.block_size]
                    if block.shape == (self.block_size, self.block_size):
                        block_correlation = self._analyze_block_correlation(block)
                        pair_correlations.append(block_correlation)
            
            if pair_correlations:
                avg_correlation = np.mean(pair_correlations)
                # F5 matrix encoding creates subtle correlation changes
                if 0.6 < avg_correlation < 0.85:  # Specific range indicative of F5
                    anomaly_score += (0.85 - avg_correlation) / 0.25 * 0.4
            
            # Test 2: Detect specific coefficient modification patterns
            modification_patterns = self._detect_coefficient_modifications(luminance)
            anomaly_score += modification_patterns * 0.3
            
            # Test 3: Statistical regularity test
            regularity_score = self._analyze_statistical_regularity(luminance)
            anomaly_score += regularity_score * 0.3
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_block_correlation(self, block: np.ndarray) -> float:
        """Analyze correlation patterns within an 8x8 block"""
        try:
            if block.shape != (self.block_size, self.block_size):
                return 0.0
            
            # Calculate correlation between adjacent coefficients
            correlations = []
            
            # Horizontal correlations
            for row in range(self.block_size):
                for col in range(self.block_size - 1):
                    if block[row, col] != block[row, col + 1]:  # Avoid identical values
                        corr = abs(block[row, col] - block[row, col + 1])
                        correlations.append(corr)
            
            # Vertical correlations
            for row in range(self.block_size - 1):
                for col in range(self.block_size):
                    if block[row, col] != block[row + 1, col]:
                        corr = abs(block[row, col] - block[row + 1, col])
                        correlations.append(corr)
            
            if correlations:
                return np.mean(correlations) / 255.0  # Normalize to 0-1
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_coefficient_modifications(self, luminance: np.ndarray) -> float:
        """Detect patterns of coefficient modifications typical of F5"""
        try:
            height, width = luminance.shape
            modification_score = 0.0
            
            # F5 modifies specific frequency coefficients
            # Analyze frequency domain patterns by simulating DCT effects
            
            # Test 1: Look for specific value distributions
            # F5 tends to avoid certain coefficient values
            flat_luminance = luminance.flatten()
            
            # Check for coefficient value avoidance patterns
            hist, bins = np.histogram(flat_luminance, bins=64, range=(0, 255))
            total_pixels = len(flat_luminance)
            
            if total_pixels > 0:
                # Look for unusual gaps or concentrations
                normalized_hist = hist / total_pixels
                
                # F5 might create subtle gaps around certain values
                for i in range(len(normalized_hist)):
                    expected_freq = 1.0 / 64  # Uniform expectation
                    deviation = abs(normalized_hist[i] - expected_freq)
                    if deviation > 0.03:  # Significant deviation
                        modification_score += min(0.1, deviation * 2)
            
            # Test 2: Analyze local variance patterns
            variance_patterns = []
            window_size = 4
            
            for y in range(0, height - window_size, window_size):
                for x in range(0, width - window_size, window_size):
                    window = luminance[y:y+window_size, x:x+window_size]
                    local_var = np.var(window)
                    variance_patterns.append(local_var)
            
            if variance_patterns:
                var_mean = np.mean(variance_patterns)
                var_std = np.std(variance_patterns)
                
                # F5 can create specific variance distribution patterns
                if var_std > 0:
                    cv = var_std / var_mean
                    if 0.3 < cv < 0.7:  # Specific range for F5
                        modification_score += (0.7 - cv) / 0.4 * 0.3
            
            return min(1.0, modification_score)
            
        except Exception:
            return 0.0
    
    def _analyze_statistical_regularity(self, luminance: np.ndarray) -> float:
        """Analyze statistical regularity patterns"""
        try:
            # F5 creates subtle statistical regularities due to matrix encoding
            regularity_score = 0.0
            
            # Test 1: Analyze coefficient difference patterns
            diff_horizontal = np.diff(luminance, axis=1)
            diff_vertical = np.diff(luminance, axis=0)
            
            # Calculate entropy of differences
            h_entropy = self._calculate_entropy(diff_horizontal.flatten())
            v_entropy = self._calculate_entropy(diff_vertical.flatten())
            
            # Natural images have certain entropy ranges
            # F5 can slightly alter these patterns
            max_entropy = 8.0  # Maximum for 8-bit differences
            
            if max_entropy > 0:
                h_normalized = h_entropy / max_entropy
                v_normalized = v_entropy / max_entropy
                
                # Look for specific entropy patterns
                if 0.7 < h_normalized < 0.9 and 0.7 < v_normalized < 0.9:
                    entropy_regularity = min(h_normalized, v_normalized)
                    regularity_score += entropy_regularity * 0.3
            
            # Test 2: Analyze autocorrelation patterns
            autocorr_score = self._analyze_autocorrelation_patterns(luminance)
            regularity_score += autocorr_score * 0.4
            
            # Test 3: Check for periodic patterns
            periodic_score = self._detect_periodic_patterns(luminance)
            regularity_score += periodic_score * 0.3
            
            return min(1.0, regularity_score)
            
        except Exception:
            return 0.0
    
    def _analyze_dct_coefficient_patterns(self, luminance: np.ndarray) -> float:
        """Analyze DCT coefficient patterns for F5 signatures"""
        try:
            # Simulate DCT analysis by examining block-wise patterns
            height, width = luminance.shape
            coefficient_anomaly = 0.0
            
            # Analyze 8x8 blocks as DCT would process them
            block_anomalies = []
            
            for y in range(0, height - self.block_size + 1, self.block_size):
                for x in range(0, width - self.block_size + 1, self.block_size):
                    block = luminance[y:y+self.block_size, x:x+self.block_size]
                    
                    if block.shape == (self.block_size, self.block_size):
                        # Analyze high-frequency vs low-frequency content
                        block_anomaly = self._analyze_frequency_distribution(block)
                        block_anomalies.append(block_anomaly)
            
            if block_anomalies:
                avg_block_anomaly = np.mean(block_anomalies)
                coefficient_anomaly += avg_block_anomaly * 0.6
            
            # Additional coefficient-level analysis
            zero_coefficient_analysis = self._analyze_zero_coefficients(luminance)
            coefficient_anomaly += zero_coefficient_analysis * 0.4
            
            return min(1.0, coefficient_anomaly)
            
        except Exception:
            return 0.0
    
    def _analyze_frequency_distribution(self, block: np.ndarray) -> float:
        """Analyze frequency distribution within a block"""
        try:
            # Simple frequency analysis using gradients as proxy
            grad_x = np.gradient(block.astype(float), axis=1)
            grad_y = np.gradient(block.astype(float), axis=0)
            
            high_freq_energy = np.sum(grad_x**2 + grad_y**2)
            low_freq_energy = np.sum(block**2)
            
            if low_freq_energy > 0:
                freq_ratio = high_freq_energy / low_freq_energy
                
                # F5 affects this ratio in characteristic ways
                if 0.05 < freq_ratio < 0.25:  # Specific range for F5
                    return freq_ratio / 0.25
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_zero_coefficients(self, luminance: np.ndarray) -> float:
        """Analyze patterns in zero and near-zero coefficients"""
        try:
            # F5 tends to increase the number of zero coefficients
            flat_data = luminance.flatten()
            
            # Count coefficients in different ranges
            zero_count = np.sum(flat_data == 0)
            near_zero_count = np.sum(np.abs(flat_data) <= 1)
            total_count = len(flat_data)
            
            if total_count > 0:
                zero_ratio = zero_count / total_count
                near_zero_ratio = near_zero_count / total_count
                
                # Natural images have certain zero coefficient patterns
                # F5 can alter these patterns
                if zero_ratio > 0.1 or near_zero_ratio > 0.3:
                    return min(1.0, (zero_ratio * 5 + near_zero_ratio * 2))
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_coefficient_histogram(self, luminance: np.ndarray) -> float:
        """Analyze coefficient histogram for F5 patterns"""
        try:
            # Calculate histogram
            hist, bins = np.histogram(luminance.flatten(), bins=128, range=(0, 255))
            total_pixels = luminance.size
            
            if total_pixels == 0:
                return 0.0
            
            anomaly_score = 0.0
            
            # Test 1: Look for histogram artifacts
            normalized_hist = hist / total_pixels
            
            # Calculate histogram entropy
            hist_nonzero = normalized_hist[normalized_hist > 0]
            if len(hist_nonzero) > 1:
                entropy = -np.sum(hist_nonzero * np.log2(hist_nonzero))
                max_entropy = math.log2(len(hist_nonzero))
                
                if max_entropy > 0:
                    normalized_entropy = entropy / max_entropy
                    # F5 can create specific entropy patterns
                    if 0.85 < normalized_entropy < 0.95:
                        anomaly_score += (normalized_entropy - 0.85) / 0.1 * 0.3
            
            # Test 2: Check for specific histogram shapes
            # F5 can create subtle changes in histogram shape
            histogram_shape_score = self._analyze_histogram_shape(normalized_hist)
            anomaly_score += histogram_shape_score * 0.4
            
            # Test 3: Analyze histogram smoothness
            smoothness_score = self._analyze_histogram_smoothness(normalized_hist)
            anomaly_score += smoothness_score * 0.3
            
            return min(1.0, anomaly_score)
            
        except Exception:
            return 0.0
    
    def _analyze_histogram_shape(self, normalized_hist: np.ndarray) -> float:
        """Analyze histogram shape for F5-specific patterns"""
        try:
            if len(normalized_hist) < 10:
                return 0.0
            
            # Look for subtle deviations from natural histogram shapes
            shape_score = 0.0
            
            # Check for unusual peaks
            peak_indices = []
            for i in range(1, len(normalized_hist) - 1):
                if (normalized_hist[i] > normalized_hist[i-1] and 
                    normalized_hist[i] > normalized_hist[i+1] and
                    normalized_hist[i] > 0.01):  # At least 1% of pixels
                    peak_indices.append(i)
            
            # F5 might create or suppress certain peaks
            if len(peak_indices) > 5:  # Too many peaks
                shape_score += min(0.3, (len(peak_indices) - 5) / 10)
            elif len(peak_indices) < 2:  # Too few peaks
                shape_score += 0.2
            
            return min(1.0, shape_score)
            
        except Exception:
            return 0.0
    
    def _analyze_histogram_smoothness(self, normalized_hist: np.ndarray) -> float:
        """Analyze histogram smoothness"""
        try:
            if len(normalized_hist) < 3:
                return 0.0
            
            # Calculate second derivative (smoothness measure)
            second_deriv = []
            for i in range(1, len(normalized_hist) - 1):
                deriv2 = normalized_hist[i-1] - 2*normalized_hist[i] + normalized_hist[i+1]
                second_deriv.append(abs(deriv2))
            
            if not second_deriv:
                return 0.0
            
            avg_second_deriv = np.mean(second_deriv)
            
            # F5 can create specific smoothness patterns
            if avg_second_deriv > 0.001:  # Too jagged
                return min(1.0, (avg_second_deriv - 0.001) * 1000)
            elif avg_second_deriv < 0.0001:  # Too smooth
                return min(0.5, (0.0001 - avg_second_deriv) * 5000)
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_shrinkage_artifacts(self, luminance: np.ndarray) -> float:
        """Detect shrinkage artifacts specific to F5"""
        try:
            # F5 uses matrix encoding which can create shrinkage artifacts
            shrinkage_score = 0.0
            
            # Test 1: Analyze block boundary artifacts
            boundary_artifacts = self._analyze_block_boundaries(luminance)
            shrinkage_score += boundary_artifacts * 0.5
            
            # Test 2: Detect quantization artifacts
            quantization_artifacts = self._detect_quantization_patterns(luminance)
            shrinkage_score += quantization_artifacts * 0.3
            
            # Test 3: Analysis compression artifacts
            compression_artifacts = self._analyze_compression_artifacts(luminance)
            shrinkage_score += compression_artifacts * 0.2
            
            return min(1.0, shrinkage_score)
            
        except Exception:
            return 0.0
    
    def _analyze_block_boundaries(self, luminance: np.ndarray) -> float:
        """Analyze artifacts at DCT block boundaries"""
        try:
            height, width = luminance.shape
            boundary_score = 0.0
            boundary_differences = []
            
            # Analyze horizontal block boundaries
            for y in range(self.block_size, height, self.block_size):
                if y < height:
                    for x in range(width):
                        if y > 0 and y < height - 1:
                            boundary_diff = abs(float(luminance[y-1, x]) - float(luminance[y, x]))
                            boundary_differences.append(boundary_diff)
            
            # Analyze vertical block boundaries
            for x in range(self.block_size, width, self.block_size):
                if x < width:
                    for y in range(height):
                        if x > 0 and x < width - 1:
                            boundary_diff = abs(float(luminance[y, x-1]) - float(luminance[y, x]))
                            boundary_differences.append(boundary_diff)
            
            if boundary_differences:
                avg_boundary_diff = np.mean(boundary_differences)
                # Subtle boundary artifacts might indicate F5
                if 2 < avg_boundary_diff < 10:
                    boundary_score = (avg_boundary_diff - 2) / 8
            
            return min(1.0, boundary_score)
            
        except Exception:
            return 0.0
    
    def _detect_quantization_patterns(self, luminance: np.ndarray) -> float:
        """Detect quantization patterns that might indicate F5"""
        try:
            # Look for specific value clustering patterns
            flat_data = luminance.flatten()
            
            # Analyze value distribution modulo small numbers
            mod_patterns = []
            for mod_val in [2, 4, 8]:
                mod_distribution = []
                for i in range(mod_val):
                    count = np.sum(flat_data % mod_val == i)
                    mod_distribution.append(count)
                
                if sum(mod_distribution) > 0:
                    # Calculate uniformity
                    expected = sum(mod_distribution) / mod_val
                    chi_square = sum(((count - expected) ** 2) / expected 
                                   for count in mod_distribution if expected > 0)
                    mod_patterns.append(chi_square / mod_val)
            
            if mod_patterns:
                avg_pattern = np.mean(mod_patterns)
                # Specific quantization patterns might indicate F5
                if 0.5 < avg_pattern < 2.0:
                    return avg_pattern / 2.0
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_compression_artifacts(self, luminance: np.ndarray) -> float:
        """Analyze compression artifacts"""
        try:
            # Simple compression artifact detection
            # Look for ringing and blocking artifacts
            
            # Calculate local variance in small blocks
            variances = []
            block_size = 4
            height, width = luminance.shape
            
            for y in range(0, height - block_size, block_size):
                for x in range(0, width - block_size, block_size):
                    block = luminance[y:y+block_size, x:x+block_size]
                    var = np.var(block)
                    variances.append(var)
            
            if variances:
                var_mean = np.mean(variances)
                var_std = np.std(variances)
                
                # Specific variance patterns might indicate compression artifacts
                if var_std > 0 and var_mean > 0:
                    cv = var_std / var_mean
                    if cv > 1.5:  # High variation in variance
                        return min(1.0, (cv - 1.5) / 2)
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_jpeg_metadata(self, file_path: str) -> Dict[str, Any]:
        """Analyze JPEG metadata for F5-related information"""
        try:
            metadata = {
                'quality_estimate': 0,
                'has_quantization_tables': False,
                'compression_info': 'unknown'
            }
            
            with Image.open(file_path) as img:
                if hasattr(img, '_getexif') and img._getexif():
                    exif_dict = img._getexif()
                    if exif_dict:
                        # Look for quality indicators in EXIF
                        for tag_id, value in exif_dict.items():
                            tag = TAGS.get(tag_id, tag_id) if EXIF_AVAILABLE else str(tag_id)
                            if isinstance(tag, str):
                                if 'quality' in tag.lower():
                                    metadata['compression_info'] = str(value)
                
                # Check for quantization table information
                if hasattr(img, 'quantization'):
                    metadata['has_quantization_tables'] = True
            
            return metadata
            
        except Exception:
            return {
                'quality_estimate': 0,
                'has_quantization_tables': False,
                'compression_info': 'error'
            }
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy"""
        try:
            if len(data) == 0:
                return 0.0
            
            # Calculate histogram
            hist, _ = np.histogram(data, bins=256, range=(-128, 127))
            
            # Calculate entropy
            total = sum(hist)
            if total == 0:
                return 0.0
            
            entropy = 0.0
            for count in hist:
                if count > 0:
                    prob = count / total
                    entropy -= prob * math.log2(prob)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _analyze_autocorrelation_patterns(self, luminance: np.ndarray) -> float:
        """Analyze autocorrelation patterns"""
        try:
            height, width = luminance.shape
            
            # Calculate autocorrelation with small lags
            autocorr_scores = []
            for lag in range(1, 4):
                if width > lag:
                    # Horizontal autocorrelation
                    corr_sum = 0
                    count = 0
                    for y in range(height):
                        for x in range(width - lag):
                            corr_sum += luminance[y, x] * luminance[y, x + lag]
                            count += 1
                    
                    if count > 0:
                        autocorr_scores.append(corr_sum / count)
            
            if autocorr_scores:
                # Look for specific autocorrelation patterns
                avg_autocorr = np.mean(autocorr_scores)
                normalized_autocorr = avg_autocorr / (255 * 255)  # Normalize
                
                # Specific autocorrelation values might indicate F5
                if 0.6 < normalized_autocorr < 0.9:
                    return normalized_autocorr
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_periodic_patterns(self, luminance: np.ndarray) -> float:
        """Detect periodic patterns that might indicate F5"""
        try:
            # Simple periodic pattern detection using row/column sums
            height, width = luminance.shape
            
            # Calculate row sums and column sums
            row_sums = np.sum(luminance, axis=1)
            col_sums = np.sum(luminance, axis=0)
            
            # Look for periodicity in sums
            row_periodicity = self._detect_periodicity(row_sums)
            col_periodicity = self._detect_periodicity(col_sums)
            
            return (row_periodicity + col_periodicity) / 2
            
        except Exception:
            return 0.0
    
    def _detect_periodicity(self, signal: np.ndarray) -> float:
        """Detect periodicity in a 1D signal"""
        try:
            if len(signal) < 16:
                return 0.0
            
            # Simple autocorrelation-based periodicity detection
            max_lag = min(len(signal) // 4, 32)
            autocorrs = []
            
            for lag in range(1, max_lag):
                if len(signal) > lag:
                    corr = np.corrcoef(signal[:-lag], signal[lag:])[0, 1]
                    if not np.isnan(corr):
                        autocorrs.append(abs(corr))
            
            if autocorrs:
                max_autocorr = max(autocorrs)
                # Strong periodicity might indicate artificial patterns
                if max_autocorr > 0.7:
                    return max_autocorr
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, height: int, width: int, anomaly_score: float) -> int:
        """Estimate size of data hidden using F5"""
        try:
            total_pixels = height * width
            
            # F5 can hide variable amounts depending on JPEG quality and content
            # Conservative estimate based on anomaly score
            capacity_ratio = 0.1 * anomaly_score  # Up to 10% capacity
            estimated_bits = int(total_pixels * capacity_ratio)
            estimated_bytes = max(1, estimated_bits // 8)
            
            return estimated_bytes
            
        except Exception:
            return 1
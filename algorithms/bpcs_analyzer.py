"""
BPCS (Bit-Plane Complexity Segmentation) Analysis Algorithm
Detects steganography using bit-plane complexity analysis
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, List, Tuple
import math

class BPCSAnalyzer:
    """BPCS steganography detection algorithm"""
    
    def __init__(self):
        self.complexity_threshold = 0.3
        self.grid_size = 8
        self.significant_planes = [4, 5, 6, 7]  # Higher bit planes more likely to contain data
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform BPCS analysis on image file"""
        try:
            with Image.open(file_path) as img:
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Analyze each color channel
                channel_results = []
                total_suspicious_planes = 0
                total_grids_analyzed = 0
                
                for channel_idx in range(channels):
                    channel_data = img_array[:, :, channel_idx]
                    channel_name = ['Red', 'Green', 'Blue'][channel_idx]
                    
                    # Analyze bit planes for this channel
                    bit_plane_results = []
                    channel_suspicious = 0
                    
                    for bit_plane in range(8):  # 0 (LSB) to 7 (MSB)
                        plane_data = self._extract_bit_plane(channel_data, bit_plane)
                        complexity_score, grid_count, suspicious_grids = self._analyze_bit_plane_complexity(plane_data)
                        
                        is_suspicious = (complexity_score > self.complexity_threshold and 
                                       bit_plane in self.significant_planes)
                        
                        if is_suspicious:
                            channel_suspicious += 1
                            total_suspicious_planes += 1
                        
                        total_grids_analyzed += grid_count
                        
                        bit_plane_results.append({
                            'bit_plane': bit_plane,
                            'complexity_score': complexity_score,
                            'grid_count': grid_count,
                            'suspicious_grids': suspicious_grids,
                            'is_suspicious': is_suspicious
                        })
                    
                    channel_results.append({
                        'channel': channel_name,
                        'suspicious_planes': channel_suspicious,
                        'bit_planes': bit_plane_results
                    })
                
                # Calculate overall confidence and verdict
                if total_grids_analyzed == 0:
                    return {
                        'status': 'error',
                        'error': 'No bit-plane grids could be analyzed'
                    }
                
                # Calculate confidence based on suspicious planes
                confidence = min(95.0, (total_suspicious_planes / (channels * len(self.significant_planes))) * 100.0)
                
                # Generate verdict
                if total_suspicious_planes >= 3:  # Multiple suspicious planes
                    status = 'found'
                    message = f'BPCS steganography detected in {total_suspicious_planes} bit-planes'
                    
                    # Estimate hidden data size
                    estimated_size = self._estimate_hidden_data_size(height, width, total_suspicious_planes)
                    
                    return {
                        'status': status,
                        'confidence': confidence,
                        'message': message,
                        'data': {
                            'type': 'binary_data',
                            'size_bytes': estimated_size,
                            'suspicious_planes': total_suspicious_planes,
                            'total_grids': total_grids_analyzed
                        },
                        'details': channel_results
                    }
                
                elif total_suspicious_planes >= 1:
                    return {
                        'status': 'weak',
                        'confidence': confidence,
                        'message': f'Weak BPCS signals in {total_suspicious_planes} bit-plane(s)',
                        'details': channel_results
                    }
                
                else:
                    return {
                        'status': 'none',
                        'confidence': 0.0,
                        'message': 'No BPCS steganography detected',
                        'details': channel_results
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'error': f'BPCS analysis failed: {str(e)}'
            }
    
    def _extract_bit_plane(self, channel_data: np.ndarray, bit_plane: int) -> np.ndarray:
        """Extract specific bit plane from channel data"""
        try:
            # Extract the specified bit plane (0 = LSB, 7 = MSB)
            return (channel_data >> bit_plane) & 1
        except Exception:
            return np.zeros_like(channel_data)
    
    def _analyze_bit_plane_complexity(self, plane_data: np.ndarray) -> Tuple[float, int, int]:
        """Analyze complexity of bit plane using grid-based approach"""
        try:
            height, width = plane_data.shape
            total_complexity = 0.0
            grid_count = 0
            suspicious_grids = 0
            
            # Process grids of specified size
            for y in range(0, height - self.grid_size + 1, self.grid_size):
                for x in range(0, width - self.grid_size + 1, self.grid_size):
                    grid = plane_data[y:y+self.grid_size, x:x+self.grid_size]
                    
                    # Calculate grid complexity
                    complexity = self._calculate_grid_complexity(grid)
                    total_complexity += complexity
                    grid_count += 1
                    
                    # Check if this grid is suspicious
                    if complexity > self.complexity_threshold:
                        suspicious_grids += 1
            
            # Average complexity across all grids
            avg_complexity = total_complexity / grid_count if grid_count > 0 else 0.0
            
            return avg_complexity, grid_count, suspicious_grids
            
        except Exception:
            return 0.0, 0, 0
    
    def _calculate_grid_complexity(self, grid: np.ndarray) -> float:
        """Calculate complexity of an 8x8 grid using border complexity measure"""
        try:
            if grid.shape != (self.grid_size, self.grid_size):
                return 0.0
            
            # Count changes along borders (horizontal and vertical)
            changes = 0
            total_comparisons = 0
            
            # Horizontal changes
            for row in range(self.grid_size):
                for col in range(self.grid_size - 1):
                    if grid[row, col] != grid[row, col + 1]:
                        changes += 1
                    total_comparisons += 1
            
            # Vertical changes
            for col in range(self.grid_size):
                for row in range(self.grid_size - 1):
                    if grid[row, col] != grid[row + 1, col]:
                        changes += 1
                    total_comparisons += 1
            
            # Calculate complexity as ratio of changes to total comparisons
            if total_comparisons > 0:
                complexity = changes / total_comparisons
            else:
                complexity = 0.0
            
            return complexity
            
        except Exception:
            return 0.0
    
    def _estimate_hidden_data_size(self, height: int, width: int, suspicious_planes: int) -> int:
        """Estimate size of hidden data based on suspicious bit planes"""
        try:
            # Each suspicious plane can potentially hide data
            # BPCS typically uses complex grids, so estimate conservatively
            
            grids_per_plane = ((height // self.grid_size) * (width // self.grid_size))
            bits_per_grid = self.grid_size * self.grid_size  # 64 bits per 8x8 grid
            
            # Estimate that suspicious planes contain some data
            estimated_bits = suspicious_planes * grids_per_plane * bits_per_grid * 0.1  # 10% usage
            estimated_bytes = max(1, int(estimated_bits // 8))
            
            return estimated_bytes
            
        except Exception:
            return 1
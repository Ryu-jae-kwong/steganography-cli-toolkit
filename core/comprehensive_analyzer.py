"""
Comprehensive Analysis Engine for Steganography Tool v5.0
Integrates all detection algorithms and provides unified analysis interface
"""

import os
import sys
import hashlib
import zipfile
import rarfile
import py7zr
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from PIL import Image, ExifTags
import numpy as np

# Import algorithm modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import actual algorithm implementations
try:
    from algorithms.lsb_analyzer import LSBAnalyzer
    from algorithms.dct_analyzer import DCTAnalyzer
    from algorithms.statistical_analyzer import StatisticalAnalyzer
    from algorithms.bpcs_analyzer import BPCSAnalyzer
    from algorithms.alpha_analyzer import AlphaAnalyzer
    from algorithms.jsteg_analyzer import JStegAnalyzer
    from algorithms.pvd_analyzer import PVDAnalyzer
    from algorithms.histogram_analyzer import HistogramAnalyzer
    from algorithms.dwt_analyzer import DWTAnalyzer
    from algorithms.f5_analyzer import F5Analyzer
except ImportError as e:
    print(f"Warning: Could not import algorithm modules: {e}")

class ComprehensiveAnalyzer:
    """Main analysis engine that coordinates all steganography detection algorithms"""
    
    SUPPORTED_FORMATS = {
        'images': ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif'],
        'archives': ['.zip', '.rar', '.7z']
    }
    
    def __init__(self):
        # Initialize algorithm instances
        try:
            self.lsb_analyzer = LSBAnalyzer()
            self.dct_analyzer = DCTAnalyzer()
            self.statistical_analyzer = StatisticalAnalyzer()
            self.bpcs_analyzer = BPCSAnalyzer()
            self.alpha_analyzer = AlphaAnalyzer()
            self.jsteg_analyzer = JStegAnalyzer()
            self.pvd_analyzer = PVDAnalyzer()
            self.histogram_analyzer = HistogramAnalyzer()
            self.dwt_analyzer = DWTAnalyzer()
            self.f5_analyzer = F5Analyzer()
            algorithms_loaded = True
        except NameError:
            algorithms_loaded = False
        
        # Map algorithm names to methods
        if algorithms_loaded:
            self.algorithms = {
                'lsb_analysis': self._run_lsb_analysis,
                'dct_analysis': self._run_dct_analysis,
                'dwt_analysis': self._run_dwt_analysis,
                'f5_analysis': self._run_f5_analysis,
                'metadata_analysis': self._analyze_metadata,
                'statistical_analysis': self._run_statistical_analysis,
                'bpcs_analysis': self._run_bpcs_analysis,
                'alpha_analysis': self._run_alpha_analysis,
                'jsteg_analysis': self._run_jsteg_analysis,
                'pvd_analysis': self._run_pvd_analysis,
                'histogram_analysis': self._run_histogram_analysis
            }
        else:
            # Fallback to placeholder algorithms
            self.algorithms = {
                'lsb_analysis': self._placeholder_algorithm,
                'dct_analysis': self._placeholder_algorithm,
                'dwt_analysis': self._placeholder_algorithm,
                'f5_analysis': self._placeholder_algorithm,
                'metadata_analysis': self._analyze_metadata,
                'statistical_analysis': self._placeholder_algorithm,
                'bpcs_analysis': self._placeholder_algorithm,
                'alpha_analysis': self._placeholder_algorithm,
                'jsteg_analysis': self._placeholder_algorithm,
                'pvd_analysis': self._placeholder_algorithm,
                'histogram_analysis': self._placeholder_algorithm
            }
        
    def analyze_single_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file for steganography"""
        try:
            file_info = self._extract_file_info(file_path)
            
            if not self._is_supported_format(file_path):
                return {
                    'file_info': file_info,
                    'error': 'Unsupported file format',
                    'summary': {'detected_algorithms': 0, 'verdict': 'clean'}
                }
            
            # Run all algorithms
            algorithm_results = []
            for alg_name, alg_func in self.algorithms.items():
                try:
                    result = alg_func(file_path)
                    result['algorithm'] = alg_name
                    algorithm_results.append(result)
                except Exception as e:
                    algorithm_results.append({
                        'algorithm': alg_name,
                        'status': 'error',
                        'error': str(e)
                    })
            
            # Generate summary
            summary = self._generate_summary(algorithm_results)
            
            return {
                'file_info': file_info,
                'algorithms': algorithm_results,
                'summary': summary
            }
            
        except Exception as e:
            return {
                'error': f"Analysis failed: {str(e)}",
                'summary': {'detected_algorithms': 0, 'verdict': 'clean'}
            }
    
    def analyze_batch(self, directory_path: str) -> List[Dict[str, Any]]:
        """Analyze all supported files in a directory"""
        results = []
        directory = Path(directory_path)
        
        if not directory.is_dir():
            return [self.analyze_single_file(directory_path)]
        
        # Find all supported files
        supported_files = []
        for ext_list in self.SUPPORTED_FORMATS.values():
            for ext in ext_list:
                supported_files.extend(directory.glob(f"**/*{ext}"))
        
        # Analyze each file
        for file_path in sorted(supported_files):
            if file_path.is_file():
                result = self.analyze_single_file(str(file_path))
                results.append(result)
        
        return results
    
    def analyze_archive(self, archive_path: str) -> Dict[str, Any]:
        """Analyze files within an archive"""
        try:
            archive_name = os.path.basename(archive_path)
            temp_dir = Path(archive_path).parent / f"temp_extract_{int(datetime.now().timestamp())}"
            
            # Extract archive
            extracted_files = self._extract_archive(archive_path, temp_dir)
            
            if not extracted_files:
                return {
                    'archive_name': archive_name,
                    'error': 'Failed to extract archive or no supported files found',
                    'files': []
                }
            
            # Analyze extracted files
            results = []
            for file_path in extracted_files:
                if self._is_supported_format(file_path):
                    result = self.analyze_single_file(file_path)
                    results.append(result)
            
            # Cleanup temporary files
            self._cleanup_temp_dir(temp_dir)
            
            return {
                'archive_name': archive_name,
                'files': results
            }
            
        except Exception as e:
            return {
                'archive_name': os.path.basename(archive_path),
                'error': f"Archive analysis failed: {str(e)}",
                'files': []
            }
    
    def _extract_file_info(self, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive file information"""
        try:
            path = Path(file_path)
            stat = path.stat()
            
            file_info = {
                'name': path.name,
                'path': str(path.absolute()),
                'size': self._format_file_size(stat.st_size),
                'size_bytes': stat.st_size,
                'type': self._get_file_type(file_path),
                'timestamp': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Calculate file hashes
            file_info['hashes'] = self._calculate_hashes(file_path)
            
            # Extract image-specific information
            if self._is_image_file(file_path):
                try:
                    with Image.open(file_path) as img:
                        file_info['dimensions'] = img.size
                        file_info['mode'] = img.mode
                        file_info['format'] = img.format
                        
                        # Extract EXIF data if available
                        if hasattr(img, '_getexif') and img._getexif():
                            exif_data = {}
                            for tag_id, value in img._getexif().items():
                                tag = ExifTags.TAGS.get(tag_id, tag_id)
                                exif_data[tag] = value
                            file_info['exif'] = exif_data
                            
                except Exception as e:
                    file_info['image_error'] = str(e)
            
            return file_info
            
        except Exception as e:
            return {
                'name': os.path.basename(file_path),
                'error': f"Failed to extract file info: {str(e)}"
            }
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA-1, and SHA-256 hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
                
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def _is_supported_format(self, file_path: str) -> bool:
        """Check if file format is supported for analysis"""
        ext = Path(file_path).suffix.lower()
        for format_list in self.SUPPORTED_FORMATS.values():
            if ext in format_list:
                return True
        return False
    
    def _is_image_file(self, file_path: str) -> bool:
        """Check if file is an image"""
        ext = Path(file_path).suffix.lower()
        return ext in self.SUPPORTED_FORMATS['images']
    
    def _get_file_type(self, file_path: str) -> str:
        """Determine file type based on extension"""
        ext = Path(file_path).suffix.lower()
        
        type_mappings = {
            '.png': 'PNG Image',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.bmp': 'BMP Image',
            '.tiff': 'TIFF Image',
            '.gif': 'GIF Image',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive'
        }
        
        return type_mappings.get(ext, f'{ext.upper()} File')
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def _extract_archive(self, archive_path: str, temp_dir: Path) -> List[str]:
        """Extract archive and return list of extracted files"""
        temp_dir.mkdir(exist_ok=True)
        extracted_files = []
        
        try:
            ext = Path(archive_path).suffix.lower()
            
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            elif ext == '.rar':
                with rarfile.RarFile(archive_path, 'r') as rar_ref:
                    rar_ref.extractall(temp_dir)
            elif ext == '.7z':
                with py7zr.SevenZipFile(archive_path, mode='r') as sz_ref:
                    sz_ref.extractall(temp_dir)
            
            # Collect all extracted files
            for file_path in temp_dir.rglob('*'):
                if file_path.is_file():
                    extracted_files.append(str(file_path))
                    
        except Exception as e:
            print(f"Warning: Failed to extract {archive_path}: {str(e)}")
        
        return extracted_files
    
    def _cleanup_temp_dir(self, temp_dir: Path) -> None:
        """Clean up temporary extraction directory"""
        try:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup temporary directory: {str(e)}")
    
    def _generate_summary(self, algorithm_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analysis summary from algorithm results"""
        detected_count = sum(1 for r in algorithm_results if r.get('status') == 'found')
        weak_count = sum(1 for r in algorithm_results if r.get('status') == 'weak')
        total_extracted = sum(r.get('data', {}).get('size_bytes', 0) for r in algorithm_results 
                             if r.get('status') == 'found')
        
        # Determine verdict
        if detected_count >= 2:
            verdict = 'positive'
        elif detected_count == 1 or weak_count > 0:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        
        return {
            'detected_algorithms': detected_count,
            'weak_signals': weak_count,
            'total_extracted_size': total_extracted,
            'verdict': verdict
        }
    
    # Placeholder algorithms (to be implemented in Phase 2)
    def _placeholder_algorithm(self, file_path: str) -> Dict[str, Any]:
        """Placeholder for algorithms to be implemented"""
        return {
            'status': 'none',
            'confidence': 0.0,
            'message': 'Algorithm not yet implemented'
        }
    
    def _analyze_metadata(self, file_path: str) -> Dict[str, Any]:
        """Basic metadata analysis implementation"""
        try:
            if not self._is_image_file(file_path):
                return {'status': 'none', 'message': 'Not an image file'}
            
            with Image.open(file_path) as img:
                # Check for hidden text in PNG chunks
                if img.format == 'PNG':
                    if hasattr(img, 'text') and img.text:
                        suspicious_keys = ['comment', 'description', 'software', 'copyright']
                        for key, value in img.text.items():
                            if key.lower() in suspicious_keys and len(value) > 100:
                                return {
                                    'status': 'found',
                                    'confidence': 85.0,
                                    'data': {
                                        'type': 'text_data',
                                        'size_bytes': len(value.encode('utf-8')),
                                        'preview': value[:100]
                                    },
                                    'message': f'Suspicious metadata in {key} field'
                                }
                
                # Check EXIF data for anomalies
                if hasattr(img, '_getexif') and img._getexif():
                    exif = img._getexif()
                    for tag_id, value in exif.items():
                        if isinstance(value, (str, bytes)) and len(str(value)) > 200:
                            return {
                                'status': 'weak',
                                'confidence': 60.0,
                                'message': f'Unusually large EXIF field: {ExifTags.TAGS.get(tag_id, tag_id)}'
                            }
            
            return {'status': 'none', 'message': 'No suspicious metadata found'}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    # New algorithm execution methods
    def _run_lsb_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute LSB analysis"""
        try:
            return self.lsb_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'LSB analysis error: {str(e)}'}
    
    def _run_dct_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute DCT analysis"""
        try:
            return self.dct_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'DCT analysis error: {str(e)}'}
    
    def _run_statistical_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute statistical analysis"""
        try:
            return self.statistical_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'Statistical analysis error: {str(e)}'}
    
    def _run_bpcs_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute BPCS analysis"""
        try:
            return self.bpcs_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'BPCS analysis error: {str(e)}'}
    
    def _run_alpha_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute Alpha channel analysis"""
        try:
            return self.alpha_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'Alpha analysis error: {str(e)}'}
    
    def _run_jsteg_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute JSteg analysis"""
        try:
            return self.jsteg_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'JSteg analysis error: {str(e)}'}
    
    def _run_pvd_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute PVD analysis"""
        try:
            return self.pvd_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'PVD analysis error: {str(e)}'}
    
    def _run_histogram_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute Histogram analysis"""
        try:
            return self.histogram_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'Histogram analysis error: {str(e)}'}
    
    def _run_dwt_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute DWT analysis"""
        try:
            return self.dwt_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'DWT analysis error: {str(e)}'}
    
    def _run_f5_analysis(self, file_path: str) -> Dict[str, Any]:
        """Execute F5 analysis"""
        try:
            return self.f5_analyzer.analyze(file_path)
        except Exception as e:
            return {'status': 'error', 'error': f'F5 analysis error: {str(e)}'}
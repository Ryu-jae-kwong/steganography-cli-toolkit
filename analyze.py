#!/usr/bin/env python3
"""
Steganography Analysis Tool v5.0
Professional image analysis for steganography detection
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
import hashlib
import numpy as np

from core.comprehensive_analyzer import ComprehensiveAnalyzer
from core.localization import LocalizationManager

def convert_numpy_types(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

def calculate_file_hashes(file_path):
    """Calculate MD5, SHA-1, and SHA-256 hashes of the file"""
    hashes = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
    except Exception as e:
        hashes = {'error': f'Failed to calculate hashes: {str(e)}'}
        
    return hashes

def format_output(results, style='minimal', lang='en'):
    """Format analysis results based on style and language"""
    
    if style == 'minimal':
        print(f"\n=== Steganography Analysis Results ===")
        print(f"File: {results.get('file_info', {}).get('name', 'Unknown')}")
        print(f"Size: {results.get('file_info', {}).get('size_mb', 0):.2f} MB")
        print(f"Analysis Time: {results.get('analysis_time', 0):.2f} seconds")
        
        print(f"\nHash Information:")
        hashes = results.get('file_info', {}).get('hashes', {})
        print(f"MD5: {hashes.get('md5', 'N/A')}")
        print(f"SHA-256: {hashes.get('sha256', 'N/A')}")
        
        print(f"\nAlgorithm Results:")
        algorithms = results.get('algorithms', [])
        if isinstance(algorithms, list):
            for algo_results in algorithms:
                algo_name = algo_results.get('algorithm', 'unknown')
                status = algo_results.get('status', 'error')
                confidence = algo_results.get('confidence', 0)
                message = algo_results.get('message', 'No message')
                
                if status == 'found':
                    print(f"{algo_name.upper()}: DETECTED ({confidence:.1f}% confidence) - {message}")
                elif status == 'none':
                    print(f"{algo_name.upper()}: Clean - {message}")
                else:
                    print(f"{algo_name.upper()}: {status} - {message}")
        else:
            for algo_name, algo_results in algorithms.items():
                status = algo_results.get('status', 'error')
                confidence = algo_results.get('confidence', 0)
                print(f"{algo_name.upper()}: {status} ({confidence:.2f} confidence)")
                
        summary = results.get('summary', {})
        print(f"\nSummary:")
        print(f"Detected Algorithms: {summary.get('detected_algorithms', 0)}")
        print(f"Total Extracted Size: {summary.get('total_extracted_size', 0)} bytes")
        print(f"Verdict: {summary.get('verdict', 'unknown').upper()}")
        
    elif style == 'detailed':
        print(json.dumps(results, indent=2, ensure_ascii=False))
        
    elif style == 'structured':
        print(json.dumps(results, ensure_ascii=False))
        
    else:  # compact, progressive
        print(f"Analysis complete: {results.get('overall_assessment', {}).get('risk_level', 'unknown')}")

def main():
    """Main analysis function"""
    
    parser = argparse.ArgumentParser(
        description="Steganography Analysis Tool v5.0 - Professional steganography detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py image.png                          # Basic analysis
  python analyze.py image.png --lang ko               # Korean output  
  python analyze.py image.py --style detailed        # Detailed analysis
        """
    )
    
    parser.add_argument("path", help="Image file to analyze")
    parser.add_argument("--lang", choices=['en', 'ko'], default='en',
                       help="Output language (default: en)")
    parser.add_argument("--style", 
                       choices=['minimal', 'detailed', 'compact', 'structured', 'progressive'],
                       default='minimal',
                       help="Output style (default: minimal)")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--comprehensive", action="store_true",
                       help="Run comprehensive analysis with all algorithms")
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.path):
        print(f"Error: File '{args.path}' not found")
        return 1
        
    if not os.path.isfile(args.path):
        print(f"Error: '{args.path}' is not a file")
        return 1
    
    print(f"Analyzing: {args.path}")
    
    try:
        # Initialize analyzer
        analyzer = ComprehensiveAnalyzer()
        
        # Perform analysis
        start_time = datetime.now()
        results = analyzer.analyze_single_file(args.path)
        end_time = datetime.now()
        
        # Add timing and file information
        results['analysis_time'] = (end_time - start_time).total_seconds()
        results['timestamp'] = datetime.now().isoformat()
        
        # Add file hashes
        file_info = results.setdefault('file_info', {})
        file_info['name'] = os.path.basename(args.path)
        file_info['size_mb'] = os.path.getsize(args.path) / (1024 * 1024)
        file_info['hashes'] = calculate_file_hashes(args.path)
        
        # Convert numpy types for JSON compatibility
        results = convert_numpy_types(results)
        
        # Format and display output
        format_output(results, args.style, args.lang)
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\nResults saved to: {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
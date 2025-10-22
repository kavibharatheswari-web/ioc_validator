#!/usr/bin/env python3
"""
Export analysis results to CSV
Exports all analysis results from the database to a CSV file
"""

import csv
from datetime import datetime
from app import app, db
from models import AnalysisResult, User

def export_to_csv():
    """Export all analysis results to CSV"""
    with app.app_context():
        # Get all analysis results
        results = AnalysisResult.query.all()
        
        if not results:
            print("⚠️  No analysis results found in database!")
            return
        
        # Create CSV filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_file = f'analysis_results_{timestamp}.csv'
        
        # Write to CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'ID', 'User Email', 'IOC', 'Type', 'Threat Score', 
                'Severity', 'Category', 'Threat Type', 'Analyzed At'
            ])
            
            # Write data
            for result in results:
                user = User.query.get(result.user_id)
                writer.writerow([
                    result.id,
                    user.email if user else 'Unknown',
                    result.ioc,
                    result.ioc_type,
                    result.threat_score,
                    result.severity,
                    result.threat_category,
                    result.threat_type,
                    result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        print("✅ Analysis results exported successfully!")
        print("")
        print("=" * 60)
        print(f"CSV File: {csv_file}")
        print(f"Total Records: {len(results)}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print("")

if __name__ == "__main__":
    export_to_csv()

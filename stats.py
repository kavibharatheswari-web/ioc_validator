#!/usr/bin/env python3
"""
Display database statistics
Shows user count, analysis count, and other metrics
"""

from app import app, db
from models import User, APIKey, AnalysisResult
from collections import Counter

def show_stats():
    """Display database statistics"""
    with app.app_context():
        # Get counts
        user_count = User.query.count()
        api_key_count = APIKey.query.count()
        analysis_count = AnalysisResult.query.count()
        
        print("\n" + "=" * 60)
        print("IOC Validator - Database Statistics")
        print("=" * 60)
        
        # User statistics
        print(f"\n📊 Users: {user_count}")
        if user_count > 0:
            users = User.query.all()
            for user in users:
                user_analyses = AnalysisResult.query.filter_by(user_id=user.id).count()
                user_keys = APIKey.query.filter_by(user_id=user.id).count()
                print(f"   • {user.username} ({user.email})")
                print(f"     - Analyses: {user_analyses}")
                print(f"     - API Keys: {user_keys}")
                print(f"     - Joined: {user.created_at.strftime('%Y-%m-%d')}")
        
        # Analysis statistics
        print(f"\n🔍 Total Analyses: {analysis_count}")
        if analysis_count > 0:
            analyses = AnalysisResult.query.all()
            
            # Count by type
            types = Counter(a.ioc_type for a in analyses)
            print("\n   By Type:")
            for ioc_type, count in types.most_common():
                print(f"   • {ioc_type}: {count}")
            
            # Count by severity
            severities = Counter(a.severity for a in analyses)
            print("\n   By Severity:")
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            for severity in severity_order:
                count = severities.get(severity, 0)
                if count > 0:
                    print(f"   • {severity}: {count}")
            
            # Average threat score
            avg_score = sum(a.threat_score or 0 for a in analyses) / len(analyses)
            print(f"\n   Average Threat Score: {avg_score:.2f}/100")
        
        # API Key statistics
        print(f"\n🔑 API Keys Configured: {api_key_count}")
        if api_key_count > 0:
            keys = APIKey.query.all()
            services = Counter(k.service_name for k in keys)
            print("\n   By Service:")
            for service, count in services.most_common():
                print(f"   • {service}: {count} user(s)")
        
        print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    show_stats()

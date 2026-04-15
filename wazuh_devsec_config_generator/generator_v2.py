#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wazuh DevSec Config Generator v2.0
Enhanced architecture with TUI, service detection, dashboard generation, and simulation mode
"""

import argparse
from pathlib import Path
from typing import Optional

from .core.config import ConfigManager
from .core.factory import ConfigurationFactory
from .core.service_detector import ServiceDetector
from .core.dashboard_generator import DashboardGenerator
from .core.simulation import WazuhSimulator
from .tui.app import WazuhTUI
from .generator import WazuhConfigGenerator


class WazuhGeneratorV2:
    """Enhanced Wazuh DevSec Generator with modern architecture"""
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("output/wazuh-custom-devsec")
        self.config_manager = ConfigManager()
        self.service_detector = ServiceDetector()
        self.dashboard_generator = DashboardGenerator(self.output_dir)
        self.simulator = WazuhSimulator(self.output_dir)
        
    def run_tui(self) -> None:
        """Run the Terminal User Interface"""
        tui = WazuhTUI()
        tui.run()
    
    def generate_with_detection(self, profile_name: str) -> None:
        """Generate configuration with automatic service detection"""
        print("🔍 Scanning for installed services...")
        detected_services = self.service_detector.scan_all_services()
        
        print(f"✅ Detected {len(detected_services)} services:")
        for service in detected_services:
            print(f"   • {service.name} ({service.service_type.value})")
        
        # Get recommendations
        recommendations = self.service_detector.get_recommended_integrations()
        if recommendations:
            print(f"\n💡 Recommended integrations: {', '.join(rec.value if hasattr(rec, 'value') else str(rec) for rec in recommendations)}")
        
        # Generate configuration
        print(f"\n⚙️  Generating configuration for profile: {profile_name}")
        
        try:
            config_factory = ConfigurationFactory(self.output_dir)
            result = config_factory.create_configuration(profile_name)
            
            # Generate dashboards
            profile = self.config_manager.get_profile(profile_name)
            if profile:
                dashboards = self.dashboard_generator.generate_all_dashboards(profile)
                print(f"📊 Generated {len(dashboards)} dashboard templates")
                
                # Generate import script
                import_script = self.dashboard_generator.generate_kibana_import_script(dashboards)
                print(f"📜 Generated import script: {import_script}")
            
            print(f"✅ Configuration generated successfully in: {self.output_dir}")
            
        except Exception as e:
            print(f"❌ Error generating configuration: {e}")
    
    def scan_services_only(self) -> None:
        """Only scan and display detected services"""
        print("🔍 Scanning for installed services...")
        
        detected_services = self.service_detector.scan_all_services()
        summary = self.service_detector.get_service_summary()
        
        print(f"\n📊 Service Detection Summary")
        print(f"   Total services detected: {summary['total_services']}")
        
        for service_type, services in summary['by_type'].items():
            print(f"\n   {service_type.title()}:")
            for service in services:
                status_icon = "✅" if service['status'] == 'running' else "❌"
                version_info = f" v{service['version']}" if service['version'] else ""
                port_info = f" :{service['port']}" if service['port'] else ""
                print(f"     {status_icon} {service['name']}{version_info}{port_info}")
        
        recommendations = summary['recommended_integrations']
        if recommendations:
            print(f"\n💡 Recommended integrations:")
            for integration in recommendations:
                print(f"   • {integration}")
    
    def run_full_simulation(self, profile_name: str) -> None:
        """Run complete simulation suite for a profile"""
        print("🎭 Running Full Wazuh Simulation Suite")
        print("=" * 50)
        
        # Generate configuration first
        print("1️⃣ Generating configuration...")
        self.generate_with_detection(profile_name)
        
        # Run full simulation
        print("\n2️⃣ Running simulation tests...")
        simulation_results = self.simulator.run_full_simulation()
        
        print("\n3️⃣ Simulation completed!")
        print(f"📁 Results saved in: {self.output_dir / 'simulation'}")
    
    def validate_configuration(self) -> None:
        """Validate generated configuration"""
        print("🔍 Validating Configuration...")
        
        # Import and run validation script
        try:
            from wazuh_devsec_config_generator.scripts.validate_config import ConfigValidator
            
            validator = ConfigValidator(self.output_dir)
            results = validator.validate_all()
            
            if results["summary"]["failed"] == 0:
                print("✅ All validations passed!")
            else:
                print(f"❌ {results['summary']['failed']} validations failed")
                
        except ImportError:
            print("⚠️  Validation script not available")
    
    def test_logs(self) -> None:
        """Test sample logs against generated rules"""
        print("🧪 Testing Sample Logs...")
        
        try:
            from wazuh_devsec_config_generator.scripts.test_logs import LogTester
            
            tester = LogTester(self.output_dir)
            if tester.load_configuration():
                results = tester.test_sample_logs()
                print(f"✅ Log testing completed: {results['tests_passed']}/{results['tests_run']} passed")
            else:
                print("❌ Failed to load configuration for testing")
                
        except ImportError:
            print("⚠️  Log testing script not available")
    
    def simulate_deployment(self) -> None:
        """Simulate deployment to Wazuh"""
        print("🚀 Simulating Deployment...")
        
        try:
            from wazuh_devsec_config_generator.scripts.deploy_simulation import DeploymentSimulator
            
            simulator = DeploymentSimulator(self.output_dir)
            results = simulator.run_deployment_simulation()
            
            if results["success"]:
                print("✅ Deployment simulation completed successfully!")
            else:
                print("❌ Deployment simulation failed")
                
        except ImportError:
            print("⚠️  Deployment simulation script not available")
    
    def create_sample_config(self) -> None:
        """Create a sample configuration using original generator"""
        print("🔄 Creating sample configuration with original generator...")
        
        original_generator = WazuhConfigGenerator()
        original_generator.run()
        
        print("✅ Sample configuration created")
    
    def show_status(self) -> None:
        """Show current system status"""
        print("📈 Wazuh DevSec Generator Status")
        print("=" * 50)
        
        # Current profile
        current_profile = self.config_manager.get_current_profile()
        if current_profile:
            print(f"📝 Current Profile: {current_profile.name}")
            print(f"   Type: {current_profile.type.value}")
            print(f"   Rules: {len(current_profile.rules_enabled)}")
            print(f"   Integrations: {len(current_profile.integrations)}")
        else:
            print("📝 No profile selected")
        
        # Available profiles
        profiles = self.config_manager.list_profiles()
        print(f"\n📋 Available Profiles: {', '.join(profiles)}")
        
        # Output directory
        if self.output_dir.exists():
            file_count = len(list(self.output_dir.rglob("*")))
            print(f"\n📁 Output Directory: {self.output_dir} ({file_count} files)")
        else:
            print(f"\n📁 Output Directory: {self.output_dir} (not generated yet)")
        
        # Service detection
        detected_services = self.service_detector.scan_all_services()
        print(f"\n🔍 Detected Services: {len(detected_services)}")


def main():
    """Main entry point for enhanced generator"""
    parser = argparse.ArgumentParser(
        description="Wazuh DevSec Config Generator v2.0 - Enhanced with TUI, service detection, and simulation"
    )
    
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch Terminal User Interface"
    )
    
    parser.add_argument(
        "--profile",
        type=str,
        help="Generate configuration for specific profile"
    )
    
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Only scan for installed services"
    )
    
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current system status"
    )
    
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Create sample configuration (original generator)"
    )
    
    parser.add_argument(
        "--simulate",
        type=str,
        help="Run full simulation for specified profile"
    )
    
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate generated configuration"
    )
    
    parser.add_argument(
        "--test-logs",
        action="store_true",
        help="Test sample logs against generated rules"
    )
    
    parser.add_argument(
        "--deploy-sim",
        action="store_true",
        help="Simulate deployment to Wazuh"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/wazuh-custom-devsec"),
        help="Output directory for generated configuration"
    )
    
    args = parser.parse_args()
    
    generator = WazuhGeneratorV2(args.output)
    
    if args.tui:
        generator.run_tui()
    elif args.scan:
        generator.scan_services_only()
    elif args.profile:
        generator.generate_with_detection(args.profile)
    elif args.status:
        generator.show_status()
    elif args.sample:
        generator.create_sample_config()
    elif args.simulate:
        generator.run_full_simulation(args.simulate)
    elif args.validate:
        generator.validate_configuration()
    elif args.test_logs:
        generator.test_logs()
    elif args.deploy_sim:
        generator.simulate_deployment()
    else:
        # Default to TUI
        generator.run_tui()


if __name__ == "__main__":
    main()

#!/usr/bin/env python
"""Run ACL tests without pytest to avoid import conflicts."""

import sys
import os

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import test modules
from tests.test_acl_engine import (
    TestACLEngineBasicScenarios,
    TestACLEngineNetworkFiltering,
    TestACLEngineMessageTypeFiltering,
)

def run_test_class(test_class, class_name):
    """Run all test methods in a test class."""
    print(f"\n{'='*60}")
    print(f"Running {class_name}")
    print('='*60)
    
    instance = test_class()
    passed = 0
    failed = 0
    
    for method_name in dir(instance):
        if method_name.startswith('test_'):
            method = getattr(instance, method_name)
            try:
                print(f"\n{method_name}...", end=' ')
                method()
                print("PASSED")
                passed += 1
            except Exception as e:
                print(f"FAILED - {str(e)}")
                failed += 1
    
    print(f"\n{class_name} Summary: {passed} passed, {failed} failed")
    return passed, failed

# Run test classes
total_passed = 0
total_failed = 0

# Test basic scenarios
p, f = run_test_class(TestACLEngineBasicScenarios, "TestACLEngineBasicScenarios")
total_passed += p
total_failed += f

# Test network filtering  
p, f = run_test_class(TestACLEngineNetworkFiltering, "TestACLEngineNetworkFiltering")
total_passed += p
total_failed += f

# Test message type filtering
p, f = run_test_class(TestACLEngineMessageTypeFiltering, "TestACLEngineMessageTypeFiltering")
total_passed += p
total_failed += f

print(f"\n{'='*60}")
print(f"TOTAL: {total_passed} passed, {total_failed} failed")
print('='*60)
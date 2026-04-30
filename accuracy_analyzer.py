#!/usr/bin/env python3
"""
Honeypot Attack Detection Accuracy Analyzer

This script analyzes the accuracy metrics of the honeypot's attack detection system.
Calculates detection rates, confidence scores, and classification accuracy.
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Honeypot.settings')
django.setup()

from HoneypotApp.models import RequestEvent, AttackLabel

def calculate_accuracy_metrics():
    """Calculate and display accuracy metrics for attack detection"""

    print('🔍 HONEYPOT ATTACK DETECTION ACCURACY ANALYSIS')
    print('=' * 60)

    # Get all requests and their labels
    total_requests = RequestEvent.objects.count()
    attack_labels = AttackLabel.objects.all()

    print(f'📊 Total Requests Analyzed: {total_requests}')

    if total_requests == 0:
        print('❌ No data available for accuracy calculation')
        return

    # Analyze attack classifications
    attack_types = {}
    confidences = []

    for label in attack_labels:
        attack_types[label.attack_type] = attack_types.get(label.attack_type, 0) + 1
        confidences.append(label.confidence)

    print(f'\n🎯 Attack Classification Distribution:')
    for attack_type, count in sorted(attack_types.items()):
        percentage = (count / total_requests) * 100
        print(f'   {attack_type}: {count} requests ({percentage:.1f}%)')

    # Calculate detection metrics
    detected_attacks = sum(count for attack_type, count in attack_types.items() if attack_type != 'Unknown')
    unknown_requests = attack_types.get('Unknown', 0)
    unlabeled_requests = total_requests - len(attack_labels)

    print(f'\n🛡️ Detection Summary:')
    print(f'   Detected Attacks: {detected_attacks}')
    print(f'   Unknown/Benign: {unknown_requests}')
    print(f'   Unlabeled Requests: {unlabeled_requests}')

    # Calculate basic detection rate
    detection_rate = (detected_attacks / total_requests) * 100 if total_requests > 0 else 0
    coverage_rate = (len(attack_labels) / total_requests) * 100 if total_requests > 0 else 0

    print(f'   Detection Rate: {detection_rate:.1f}%')
    print(f'   Analysis Coverage: {coverage_rate:.1f}%')

    # Confidence analysis
    if confidences:
        avg_confidence = sum(confidences) / len(confidences)
        high_confidence = sum(1 for c in confidences if c >= 0.8)
        medium_confidence = sum(1 for c in confidences if 0.5 <= c < 0.8)
        low_confidence = sum(1 for c in confidences if c < 0.5)

        print(f'\n📈 Confidence Score Analysis:')
        print(f'   Average Confidence: {avg_confidence:.3f}')
        print(f'   High Confidence (≥0.8): {high_confidence} detections')
        print(f'   Medium Confidence (0.5-0.8): {medium_confidence} detections')
        print(f'   Low Confidence (<0.5): {low_confidence} detections')

    # Attack type specific analysis
    print(f'\n🎯 Attack Type Performance:')
    for attack_type, count in sorted(attack_types.items()):
        if attack_type != 'Unknown':
            type_confidences = [label.confidence for label in attack_labels if label.attack_type == attack_type]
            if type_confidences:
                avg_type_conf = sum(type_confidences) / len(type_confidences)
                print(f'   {attack_type}:')
                print(f'      Count: {count}')
                print(f'      Avg Confidence: {avg_type_conf:.3f}')
                print(f'      Success Rate: {(count / len(attack_labels)) * 100:.1f}% of classifications')

    # Calculate accuracy metrics (simplified for honeypot context)
    print(f'\n📊 ACCURACY METRICS (Honeypot Context):')

    # In honeypot context:
    # - TP: Attacks correctly detected (attacks labeled with specific types)
    # - TN: Benign requests correctly identified (Unknown labels)
    # - FP: Benign requests incorrectly flagged (low confidence Unknown)
    # - FN: Attacks missed (no labels or very low confidence)

    # Simplified calculation
    tp = detected_attacks  # Attacks detected
    tn = unknown_requests  # Assumed benign
    fp = 0  # We don't have clear false positives without ground truth
    fn = unlabeled_requests  # Requests not analyzed

    print(f'   True Positives (TP): {tp} - Detected attacks')
    print(f'   True Negatives (TN): {tn} - Identified benign')
    print(f'   False Positives (FP): {fp} - Unknown (no ground truth)')
    print(f'   False Negatives (FN): {fn} - Unanalyzed requests')

    # Calculate standard metrics where possible
    if tp + tn + fp + fn > 0:
        accuracy = (tp + tn) / (tp + tn + fp + fn) * 100
        print(f'\\n✅ Accuracy: {accuracy:.1f}%')

    if tp + fp > 0:
        precision = tp / (tp + fp) * 100
        print(f'🎯 Precision: {precision:.1f}%')

    if tp + fn > 0:
        recall = tp / (tp + fn) * 100
        print(f'🔍 Recall: {recall:.1f}%')

    if precision + recall > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
        print(f'🏆 F1 Score: {f1_score:.1f}%')

    print(f'\n💡 INTERPRETATION:')
    print(f'   • Detection Rate: {detection_rate:.1f}% of requests were flagged as attacks')
    print(f'   • Analysis Coverage: {coverage_rate:.1f}% of requests were analyzed')
    if confidences:
        print(f'   • Confidence Quality: {avg_confidence:.2f} average confidence score')
    print(f'   • System Status: {"🟢 Active" if total_requests > 0 else "🔴 No Data"}')

    print(f'\n' + '=' * 60)
    print('Analysis completed successfully!')
    print('=' * 60)

if __name__ == "__main__":
    calculate_accuracy_metrics()
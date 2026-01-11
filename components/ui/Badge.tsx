
import React from 'react';
import { TestStatus } from '../../types';

interface BadgeProps {
  status: TestStatus | string;
}

export const StatusBadge: React.FC<BadgeProps> = ({ status }) => {
  const getColors = () => {
    switch (status) {
      case TestStatus.BLOCKED:
        return 'bg-green-900/30 text-green-400 border-green-800';
      case TestStatus.PASSED:
        return 'bg-red-900/30 text-red-400 border-red-800';
      case TestStatus.RUNNING:
        return 'bg-blue-900/30 text-blue-400 border-blue-800 animate-pulse';
      case TestStatus.ERROR:
        return 'bg-orange-900/30 text-orange-400 border-orange-800';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <span className={`px-2 py-0.5 text-xs font-semibold border rounded-full ${getColors()}`}>
      {status.toUpperCase()}
    </span>
  );
};

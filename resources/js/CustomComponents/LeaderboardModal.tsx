import React, { useState } from 'react';
import { X, CheckCheck, Trophy } from 'lucide-react';
import AnimatedLeaderboard from './AnimatedLeaderboard';

const CustomModal = ({ isOpen, onClose, children }) => {
  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <div 
        className="relative bg-white rounded-xl shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 z-10 p-2 rounded-full hover:bg-gray-100 transition-colors"
        >
          <X className="w-6 h-6 text-gray-600" />
        </button>
        {children}
      </div>
    </div>
  );
};
type Props = {}

const LeaderboardModal = ({ 
  isOpen, 
  onClose, 
  leaderboard, 
  team_id, 
  state, 
  currentQuestion 
}) => {
  return (
    <CustomModal isOpen={isOpen} onClose={onClose}>
      <div className="w-[700px] p-6">
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            Overall Leaderboard
          </h2>
          <p className="text-gray-600">
            View the current standings and team performance
          </p>
        </div>

        <div className="bg-gradient-to-br from-orange-50 to-orange-100 p-6 rounded-xl shadow-lg border border-orange-200">
          <div className="flex items-center gap-x-4 mb-6">
            <Trophy className="text-orange-700 w-10 h-10" />
            <h1 className="text-orange-700 font-semibold text-3xl">
              Overall Leaderboard
            </h1>
          </div>

          <div className="overflow-x-auto">
<table className="w-full border-separate border-spacing-y-3">
  <thead>
    <tr>
      <th className="text-left text-orange-700 font-semibold pb-2 w-auto">
        Rank & Team
      </th>
      <th className="text-left text-orange-700 font-semibold pb-2 w-32">
        Total Points
      </th>
    </tr>
  </thead>
  <tbody>
    {leaderboard.map((rank, index) => {
      // Calculate score based on state and previous answer
      let displayScore;
      if (state !== 'over-all-leaderboard') {
        displayScore = rank.prev_answer_correct === 1 
          ? (currentQuestion?.points || 0)
          : 0;
      } else {
        displayScore = rank.score <= 0 ? 0 : rank.score;
      }

      return (
        <tr
          key={rank.rank}
          className={`${
            rank.id === team_id
              ? 'bg-orange-500/50 rounded-md hover:bg-orange-500/50'
              : 'hover:bg-orange-200/50'
          } transition-colors duration-200`}
        >
          <td className="py-2 w-auto">
            <div className="flex items-center gap-x-4">
              <div className="text-xl font-bold py-2 px-4 bg-gradient-to-r from-orange-500 to-orange-600 rounded-lg shadow-md shadow-orange-200">
                <span className="text-white">{index + 1}</span>
              </div>
              <div className="text-xl font-bold py-2 px-4 rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200">
                <span className="text-orange-900">{rank.team}</span>
              </div>
            </div>
          </td>

          <td className="py-2 w-32">
            <div className="text-xl font-bold py-2 px-4 rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200 text-orange-900">
              {displayScore}
            </div>
          </td>
        </tr>
      );
    })}
  </tbody>
</table>
          </div>
        </div>
      </div>
    </CustomModal>
  );
};

export default LeaderboardModal
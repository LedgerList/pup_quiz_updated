import React, { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { TrendingUp, BookOpen, Award, Target, LayoutDashboardIcon, Search, ChevronLeft, Download, FileSpreadsheet } from 'lucide-react';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { router, usePage } from '@inertiajs/react';
import axios from 'axios';
import Swal from 'sweetalert2';
const QuizStatisticsDashboard = () => {
  const { questions: allQuestions, categories: allCategories, topLobbyCategory, lobbies } = usePage().props
  const [selectedLobby, setSelectedLobby] = useState<number | null>(null);
  const [lobbySearchTerm, setLobbySearchTerm] = useState('');
  const [availableLobbies, setAvailableLobbies] = useState<any[]>([]);
  const [questions, setQuestions] = useState(allQuestions || []);
  const [categories, setCategories] = useState(allCategories || []);
  const [totalEasyQuestion, setTotalEasyQuestion] = useState(0)
  const [totalAverageQuestion, setTotalAverageQuestion] = useState(0)
  const [byLevel, setByLevel] = useState<any>()
  const [categoriesQuestions, setCategoriesQuestions] = useState([])
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [selectedSubjectId, setSelectedSubjectId] = useState<number | null>(null)

  useEffect(() => {
    if (lobbies && lobbies.length > 0) {
      setAvailableLobbies(lobbies);
      if (!selectedLobby && lobbies[0]) {
        setSelectedLobby(lobbies[0].id);
      }
    }
  }, [lobbies]);

  useEffect(() => {
    if (!selectedLobby) {
      setQuestions(allQuestions || []);
      setCategories(allCategories || []);
      setSelectedSubjectId(allCategories?.[0]?.id || null);
      return;
    }

    // Filter questions and categories by selected lobby
    const filteredCategories = (allCategories || []).filter((cat: any) => cat.lobby_id === selectedLobby);
    const filteredCategoryIds = filteredCategories.map((cat: any) => cat.id);
    const filteredQuestions = (allQuestions || []).filter((q: any) => filteredCategoryIds.includes(q.subject_id));

    setCategories(filteredCategories);
    setQuestions(filteredQuestions);
    setSelectedSubjectId(filteredCategories?.[0]?.id || null);
  }, [selectedLobby, allQuestions, allCategories]);

  const filteredLobbies = availableLobbies.filter(lobby =>
    lobby.name.toLowerCase().includes(lobbySearchTerm.toLowerCase())
  );
  // Mock data - replace with your actual data source
  const [questionStats] = useState({
    byLevel: [
      { level: 'Beginner', count: 45, percentage: 35 },
      { level: 'Intermediate', count: 38, percentage: 30 },
      { level: 'Advanced', count: 28, percentage: 22 },
      { level: 'Expert', count: 17, percentage: 13 }
    ],
    total: 128,
    categories: [
      { name: 'Science', count: 32, color: '#f97316' },
      { name: 'History', count: 28, color: '#ea580c' },
      { name: 'Literature', count: 24, color: '#dc2626' },
      { name: 'Mathematics', count: 22, color: '#c2410c' },
      { name: 'Geography', count: 22, color: '#9a3412' }
    ]
  });
  const redShades = [
    "#f97316", // standard red
    "#ea580c", // dark red
    "#dc2626", // light red
    "#c2410c", // pastel red
    "#9a3412", // coral/red

  ];
  useEffect(() => {
    if (!questions) return
    const easy = questions.filter(q => q.difficulty === "easy");
    const average = questions.filter(q => q.difficulty === "average");
    const hard = questions.filter(q => q.difficulty === "hard");

    const total = easy.length + average.length + hard.length;

    const toPercentage = (count: number) => total === 0 ? 0 : parseFloat(((count / total) * 100).toFixed(2));

    setByLevel([
      { level: 'Easy', count: easy.length, percentage: toPercentage(easy.length) },
      { level: 'Average', count: average.length, percentage: toPercentage(average.length) },
      { level: 'Hard', count: hard.length, percentage: toPercentage(hard.length) },
    ]);
  }, [questions])
  useEffect(() => {
    if (!questions || !categories) {
      setCategoriesQuestions([]);
      return;
    }
    
    // Count questions per subject_id
    const questionCounts = questions?.reduce((acc: any, q: any) => {
      acc[q.subject_id] = (acc[q.subject_id] || 0) + 1;
      return acc;
    }, {});

    const result = categories?.map((subject: any, index: number) => ({
      name: subject.subject_name,
      count: questionCounts[subject.id] || 0,
      color: redShades[index % redShades.length]
    }));
    setCategoriesQuestions(result || [])
  }, [categories, questions])
  const handleGenerateReport = async () => {
    if (!selectedLobby || !selectedSubjectId) {
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'warning',
        title: 'Please select a quiz event and category',
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true,
      });
      return;
    }

    setIsGeneratingReport(true);
    try {
      const response = await axios.get(`/report/teams/excel/${selectedLobby}/${selectedSubjectId}`, {
        responseType: 'blob',
      });

      if (response.status === 200) {
        let filename = 'teams_report.xlsx';
        const contentDisposition = response.headers['content-disposition'];
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
          if (filenameMatch && filenameMatch[1]) {
            filename = filenameMatch[1];
          }
        }

        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);

        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Report downloaded successfully!',
          showConfirmButton: false,
          timer: 3000,
          timerProgressBar: true,
        });
      }
    } catch (error: any) {
      console.error('Error during report download:', error);
      let errorMessage = 'An error occurred during download.';
      
      if (error.response) {
        errorMessage = error.response.data?.message || `Server error: ${error.response.status}`;
      } else if (error.request) {
        errorMessage = 'No response from server. Please check your connection.';
      } else {
        errorMessage = error.message || 'An unexpected error occurred.';
      }
      
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'error',
        title: errorMessage,
        showConfirmButton: false,
        timer: 4000,
        timerProgressBar: true,
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const StatCard = ({ icon: Icon, title, value, subtitle, gradient }) => (
    <div className={`bg-gradient-to-br ${gradient} rounded-xl p-6 text-white shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02]`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-white/80 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold mt-2">{typeof value == "string" ? value?.toUpperCase() : value}</p>
          {subtitle && <p className="text-white/70 text-xs mt-1">{subtitle}</p>}
        </div>
        <Icon className="h-8 w-8 text-white/80" />
      </div>
    </div>
  );

  return (
    <AuthenticatedLayout>
      <div className="min-h-screen bg-gradient-to-br from-red-50 to-red-100 flex flex-col p-6">
        <div className="max-w-7xl mx-auto w-full">
          <div className="flex gap-6">
            {/* Left Sidebar - Quiz Event Filter */}
            <div className="w-80 flex-shrink-0">
              <div className="bg-white rounded-xl shadow-lg p-6">
                <h2 className="text-xl font-bold text-red-600 mb-2">Quiz Event</h2>
                <p className="text-sm text-gray-600 mb-4">Select a quiz event to filter statistics</p>
                
                <div className="relative mb-4">
                  <input
                    type="text"
                    placeholder="Search quiz event..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                    value={lobbySearchTerm}
                    onChange={(e) => setLobbySearchTerm(e.target.value)}
                  />
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                </div>

                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {filteredLobbies.length === 0 ? (
                    <p className="text-gray-500 text-sm text-center py-4">No quiz events found</p>
                  ) : (
                    filteredLobbies.map((lobby) => (
                      <button
                        key={lobby.id}
                        onClick={() => setSelectedLobby(lobby.id)}
                        className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${
                          selectedLobby === lobby.id
                            ? 'bg-orange-500 text-white'
                            : 'bg-gray-50 hover:bg-gray-100 text-gray-900'
                        }`}
                      >
                        {lobby.name}
                      </button>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Right Content - Statistics Dashboard */}
            <div className="flex-1">
              <div className='bg-white/80 backdrop-blur-sm rounded-xl shadow-lg p-6 space-y-6'>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h1 className="text-3xl font-bold text-red-800 tracking-tight">Question Statistics</h1>
                    {selectedLobby && (
                      <span className="text-sm text-gray-600">
                        - {availableLobbies.find(l => l.id === selectedLobby)?.name || ''}
                      </span>
                    )}
                  </div>
                  <div className="flex gap-3">
                    {selectedLobby && selectedSubjectId && (
                      <button
                        onClick={handleGenerateReport}
                        disabled={isGeneratingReport}
                        className='bg-orange-600 text-white p-4 flex gap-x-3 rounded-md hover:bg-orange-700 hover:cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors'
                        type="button"
                      >
                        <FileSpreadsheet className="w-5 h-5" />
                        <p>{isGeneratingReport ? 'Generating...' : 'Generate Report'}</p>
                      </button>
                    )}
                    <button
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        router.get("/organizerLobby");
                      }}
                      className='bg-red-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-red-700 hover:cursor-pointer cursor-pointer'
                      type="button"
                    >
                      <LayoutDashboardIcon />
                      <p>Go to Dashboard</p>
                    </button>
                  </div>
                </div>


            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <StatCard
                icon={BookOpen}
                title="Total Questions"
                value={questions?.length || 0}
                subtitle="Across all levels"
                gradient="from-red-500 to-red-600"
              />
              <StatCard
                icon={TrendingUp}
                title="Level with Highest Correct Percentage"
                value={topLobbyCategory?.difficulty}
                subtitle={`${topLobbyCategory?.total_questions || 0} questions`}
                gradient="from-red-600 to-red-700"
              />
              <StatCard
                icon={Target}
                title="Categories"
                value={categories.length}
                subtitle="Active categories"
                gradient="from-red-700 to-red-800"
              />
              <StatCard
                icon={Award}
                title="Completion Rate"
                value="100%"
                subtitle="Average across levels"
                gradient="from-red-800 to-red-900"
              />
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Bar Chart - Questions by Level */}
              <div className="bg-white/90 backdrop-blur-sm rounded-xl shadow-lg p-6 border border-red-200">
                <h3 className="text-xl font-semibold text-red-800 mb-4">Questions by Difficulty Level</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={byLevel}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#fecaca" />
                    <XAxis
                      dataKey="level"
                      stroke="#dc2626"
                      fontSize={12}
                    />
                    <YAxis
                      stroke="#dc2626"
                      fontSize={12}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#fef2f2',
                        border: '1px solid #fecaca',
                        borderRadius: '8px'
                      }}
                    />
                    <Bar
                      dataKey="count"
                      fill="url(#redGradient)"
                      radius={[4, 4, 0, 0]}
                    />
                    <defs>
                      <linearGradient id="redGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#ef4444" />
                        <stop offset="100%" stopColor="#dc2626" />
                      </linearGradient>
                    </defs>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Pie Chart - Questions by Category */}
              <div className="bg-white/90 backdrop-blur-sm rounded-xl shadow-lg p-6 border border-red-200">
                <h3 className="text-xl font-semibold text-red-800 mb-4">Questions by Category</h3>
                <ResponsiveContainer width="100%" height={300}>
                  {/* <PieChart>
                    <Pie
                      data={categoriesQuestions}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="count"
                    >
                      {categoriesQuestions.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#fff7ed',
                        border: '1px solid #fed7aa',
                        borderRadius: '8px'
                      }}
                    />
                  </PieChart>
                   */}
                  <PieChart>
                    <Pie
                      data={categoriesQuestions}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="count"
                    >
                      {categoriesQuestions.map((entry, index) => {
                        // Red color palette with different shades
                        const redColors = [
                          '#fca5a5', // red-300
                          '#f87171', // red-400
                          '#ef4444', // red-500
                          '#dc2626', // red-600
                          '#b91c1c', // red-700
                          '#991b1b', // red-800
                          '#7f1d1d', // red-900
                          '#fda4af', // rose-300
                          '#f43f5e', // rose-500
                          '#e11d48', // rose-600
                          '#be123c', // rose-700
                          '#9f1239'  // rose-800
                        ];

                        return (
                          <Cell
                            key={`cell-${index}`}
                            fill={redColors[index % redColors.length]}
                          />
                        );
                      })}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#fff1f2',
                        border: '1px solid #fda4af',
                        borderRadius: '8px'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-4 space-y-2">
                  {categoriesQuestions.map((category, index) => {
                    const categoryData = categories.find((cat: any) => cat.subject_name === category.name);
                    const isSelected = selectedSubjectId === categoryData?.id;
                    return (
                      <div 
                        key={index} 
                        className={`flex items-center justify-between text-sm p-2 rounded-lg cursor-pointer transition-colors ${
                          isSelected ? 'bg-red-100 border-2 border-red-500' : 'hover:bg-red-50'
                        }`}
                        onClick={() => categoryData && setSelectedSubjectId(categoryData.id)}
                      >
                        <div className="flex items-center space-x-2">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: category.color }}
                          ></div>
                          <span className={`font-medium ${isSelected ? 'text-red-800' : 'text-red-700'}`}>
                            {category.name}
                          </span>
                          {isSelected && (
                            <span className="text-xs bg-red-500 text-white px-2 py-0.5 rounded-full">Selected</span>
                          )}
                        </div>
                        <span className="font-semibold text-red-800">{category.count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

                {/* Detailed Level Breakdown */}
                <div className="bg-white/90 backdrop-blur-sm rounded-xl shadow-lg p-6 border border-red-200">
                  <h3 className="text-xl font-semibold text-red-800 mb-6">Detailed Level Breakdown</h3>
                  <div className="space-y-4">
                    {byLevel?.map((level, index) => (
                      <div key={index} className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-100">
                        <div className="flex items-center space-x-4">
                          <div className="w-12 h-12 bg-gradient-to-r from-red-500 to-red-600 rounded-full flex items-center justify-center text-white font-bold">
                            {level.level.charAt(0)}
                          </div>
                          <div>
                            <h4 className="font-semibold text-red-800">{level.level}</h4>
                            <p className="text-sm text-red-600">{level.count} questions ({level.percentage}%)</p>
                          </div>
                        </div>
                        <div className="w-32 bg-red-200 rounded-full h-2">
                          <div
                            className="bg-gradient-to-r from-red-500 to-red-600 h-2 rounded-full transition-all duration-500"
                            style={{ width: `${level.percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AuthenticatedLayout>

  );
};

export default QuizStatisticsDashboard;
import React from "react";

import '@fortawesome/fontawesome-free/css/all.min.css';


const FeaturesSection = () => {
  const features = [
    {
      icon: "fas fa-check-circle",
      title: "Task Organization",
      description: "Keep your tasks organized with custom lists, tags, and priorities.",
    },
    {
      icon: "fas fa-bell",
      title: "Smart Reminders",
      description: "Never miss a deadline with intelligent notifications and reminders.",
    },
    {
      icon: "fas fa-chart-line",
      title: "Progress Tracking",
      description: "Monitor your productivity with detailed analytics and reports.",
    },
    {
      icon: "fas fa-users",
      title: "Team Collaboration",
      description: "Work together seamlessly with team sharing and real-time updates.",
    },
  ];

  return (
<div className="bg-white">
  <div className="max-w-7xl mx-auto py-20 px-4 sm:px-6 lg:py-28 lg:px-8">
    <div className="max-w-3xl mx-auto text-center">
      <h2 className="text-3xl font-extrabold text-gray-800">All-in-one platform for task management</h2>
      <p className="mt-4 text-lg text-gray-600">Everything you need to manage your tasks efficiently and boost productivity.</p>
    </div>
    <dl className="mt-12 space-y-10 sm:space-y-0 sm:grid sm:grid-cols-4 sm:gap-x-6 sm:gap-y-12 lg:gap-x-8">
      <div className="relative">
        <dt>
          <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-indigo-600 text-white">
            <i className="fas fa-tasks text-2xl"></i>
          </div>
          <p className="ml-16 text-lg leading-6 font-medium text-gray-800">Task Organization</p>
        </dt>
        <dd className="mt-2 ml-16 text-base text-gray-600">Keep your tasks organized with custom lists, tags, and priorities.</dd>
      </div>
      <div className="relative">
        <dt>
          <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-indigo-600 text-white">
            <i className="fas fa-bell text-2xl"></i>
          </div>
          <p className="ml-16 text-lg leading-6 font-medium text-gray-800">Smart Reminders</p>
        </dt>
        <dd className="mt-2 ml-16 text-base text-gray-600">Never miss a deadline with intelligent notifications and reminders.</dd>
      </div>
      <div className="relative">
        <dt>
          <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-indigo-600 text-white">
            <i className="fas fa-chart-line text-2xl"></i>
          </div>
          <p className="ml-16 text-lg leading-6 font-medium text-gray-800">Progress Tracking</p>
        </dt>
        <dd className="mt-2 ml-16 text-base text-gray-600">Monitor your productivity with detailed analytics and reports.</dd>
      </div>
      <div className="relative">
        <dt>
          <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-indigo-600 text-white">
            <i className="fas fa-users text-2xl"></i>
          </div>
          <p className="ml-16 text-lg leading-6 font-medium text-gray-800">Team Collaboration</p>
        </dt>
        <dd className="mt-2 ml-16 text-base text-gray-600">Work together seamlessly with team sharing and real-time updates.</dd>
      </div>
    </dl>
  </div>
</div>

  );
};

export default FeaturesSection;

import React from "react";

const HeroSection = () => {
  return (
    <div className="relative bg-gray-900">
  <div className="absolute inset-0 bg-gradient-to-r from-indigo-500 via-indigo-600 to-indigo-800 mix-blend-multiply"></div>
  <div className="relative px-4 py-16 sm:px-6 sm:py-24 lg:py-32 lg:px-8">
    <h1 className="text-center text-4xl font-extrabold tracking-tight sm:text-5xl lg:text-6xl">
      <span className="block text-white">Take control of your tasks</span>
      <span className="block text-indigo-300">with TaskMaster</span>
    </h1>
    <p className="mt-6 max-w-lg mx-auto text-center text-xl text-indigo-100 sm:max-w-3xl">
      Streamline your workflow, boost productivity, and never miss a deadline again with our intuitive task management solution.
    </p>
    <div className="mt-10 max-w-sm mx-auto sm:max-w-none sm:flex sm:justify-center">
      <div className="space-y-4 sm:space-y-0 sm:mx-auto sm:inline-grid sm:grid-cols-2 sm:gap-5">
        <a href="#" className="flex items-center justify-center px-4 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-indigo-700 bg-white hover:bg-gray-50 sm:px-8">Get started</a>
        <a href="#" className="flex items-center justify-center px-4 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-indigo-700 hover:bg-indigo-800 sm:px-8">Live demo</a>
      </div>
    </div>
  </div>
</div>

  );
};

export default HeroSection;

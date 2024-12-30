import React from "react";

const PricingSection = () => {
  const pricingPlans = [
    {
      name: "Basic",
      price: "$10/month",
      features: [
        "Task organization",
        "Smart reminders", 
        "Basic reporting"
      ]
    },
    {
      name: "Pro",
      price: "$25/month",
      features: [
        "Advanced task organization",
        "Smart reminders",
        "Detailed reporting",
        "Team collaboration"
      ]
    },
    {
      name: "Enterprise", 
      price: "$50/month",
      features: [
        "All Pro features",
        "Dedicated support",
        "Custom integrations"
      ]
    }
  ];

  return (
    <div className="bg-gray-50 py-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-gray-900 mb-4">Simple, Transparent Pricing</h2>
          <p className="text-xl text-gray-600">Choose the plan that works best for you</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {pricingPlans.map((plan) => (
            <div 
              key={plan.name}
              className="relative p-8 bg-white rounded-2xl shadow-xl border border-gray-100 hover:scale-105 transition-transform duration-300"
            >
              <h3 className="text-2xl font-bold text-gray-900 mb-4">{plan.name}</h3>
              <div className="flex items-baseline mb-8">
                <span className="text-5xl font-extrabold text-gray-900">{plan.price.split('/')[0]}</span>
                <span className="text-xl text-gray-500 ml-1">/month</span>
              </div>
              
              <ul className="space-y-4 mb-8">
                {plan.features.map((feature, index) => (
                  <li key={index} className="flex items-center space-x-3">
                    <svg className="h-5 w-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                    </svg>
                    <span className="text-gray-600">{feature}</span>
                  </li>
                ))}
              </ul>

              <button className="w-full py-4 px-8 text-center text-white font-bold bg-indigo-600 rounded-xl hover:bg-indigo-700 transition-colors duration-200">
                Get Started
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PricingSection;

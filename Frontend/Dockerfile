# Use the official Nginx image to serve the built frontend
FROM nginx:alpine

# Copy the build files to the Nginx server's root directory
COPY build/ /usr/share/nginx/html/

# Expose the port the frontend will run on (default 80 for Nginx)
EXPOSE 5000

# Command to run Nginx
CMD ["nginx", "-g", "daemon off;"]


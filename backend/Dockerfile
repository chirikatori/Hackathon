# Bước 1: Sử dụng Maven và JDK 17 để build ứng dụng
# Tạo một image để build project trước.
FROM maven:3.8.5-openjdk-17-slim AS build

# Đặt thư mục làm việc trong container
WORKDIR /app

# Copy toàn bộ mã nguồn vào container
COPY . .

# Build ứng dụng bằng Maven, bỏ qua phần kiểm thử (tests)
RUN mvn clean package -DskipTests

# Bước 2: Tạo image chỉ chứa ứng dụng đã build xong để chạy
# Sử dụng JDK 17 nhưng không cần Maven nữa
FROM openjdk:17-jdk-slim

# Đặt thư mục làm việc trong container
WORKDIR /app

# Copy file JAR đã build từ bước trước vào container
COPY --from=build /app/target/*.jar app.jar

# Mở cổng 8080 để ứng dụng có thể truy cập từ bên ngoài container
EXPOSE 8080

# Lệnh để chạy ứng dụng khi container khởi động
ENTRYPOINT ["java", "-jar", "app.jar"]

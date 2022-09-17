# Jwt-Redis-Server

### ✅Security + JWT 기본 동작 원리

![Untitled](https://user-images.githubusercontent.com/91618389/186607982-3b6429fd-7007-4514-b3f2-9d19ad6f86ce.png)

### ✅Access Token

- sub : 사용자 고유 id
- role : 권한 정보
- expire Time : 30 mins

### ✅Refresh Token

- expire Time : 24 hours

### ✅Redis : key - value

![1](https://user-images.githubusercontent.com/91618389/186608275-6b02ba78-ab5c-434f-8c24-b2c7f42d00ae.png)

- Redis에 Token을 넣어서 관리함으로써, Client가 가지고 있는 Token들에 대해서 관리하기 위해서
→ 일종의 Session과 비슷한 역할을 담당하고 있다.
→ Redis에서 누가 로그아웃 했고, 누구의 Refresh Token을 가지고 있는지 알 수 있다.

- 왜 Redis에 refresh token과 clientIP , userID를 저장했는가?
    - 로그인 성공한 시점에 발급된 Refresh Token이 Key값으로 Redis에 저장된다.
    - 따라서 Refresh Token 만으로 다시 재발급 요청을 진행, Refresh Token에는 따로 userId를 저장하지 않기 때문에 → 서버에 따로 저장하기 위해 Redis를 사용한다.
    
- ClientIP는 왜 저장하는가?
    - 기본적으로 cookie에 대한 XSS 공격을 막기 위해 Http Only와 Secure를 설정해주고 있다.
    - CSRF 공격을 생각하여, Refresh Token이 탈취당하더라도 토큰 재발급 요청한 해커의 IP와 Redis에 저장된 ClientIP와 다르기 때문에 
    → Exception 처리 및 Refresh Token을 Redis에서 삭제
    - Refresh Token을 처음으로 제공했던 IP와 같은 경우에만 재발급 진행
    
    - 좀 더 고려할 사항)
        - 사용자가 집에서 이용하다가, 카페로 가서 카페의 IP로 재발급 요청을 보내면
        - 처음 IP와 맞지 않다고 생각하여, 재로그인 필요
    

![2](https://user-images.githubusercontent.com/91618389/186608418-421073ae-216f-41df-af4c-23150dd5e389.png)

- private 변수로 Access token을 저장하게 되면서 Refresh Token을 재발급해야 한다. 이를 위해서는 UserID가 필요하다.
- 데이터 액세스 접근 권한이 있는 UserID를 담은 Access Token이 유지되는 기가은 길면 좋지 않다.
- 따라서 Access Token의 유지기간을 짧게 가져가고, Refresh Token으로 재발급을 요청하는 구조로 방향 설정
- Refresh Token 생성시 UserID를 담는것은 Access Token과 다를바가 없다.
따라서 서버에서 Refresh Token에 대응하는 UserID를 저장하는 것이 적절하다고 판단

### ✅Redis를 사용하는 이유

- Session은 하나의 WAS가 종료되면 Session도 삭제가 된다.

![3](https://user-images.githubusercontent.com/91618389/186608547-0139aef7-bacc-47bf-9e3c-8cb54eb06b68.png)

- Redis에 Refresh Token을 저장함으로써, WAS가 종료되어도 데이터가 지워지지 않는다.
Redis를 담당하고 있는 서버를 완전 리부팅 하는 경우에만 리셋된다.

![4](https://user-images.githubusercontent.com/91618389/186608664-fa3e4b64-50af-414e-99c7-887758075db5.png)

- WAS1과 WAS2가 존재하고 만약 **무중단 배포를 위해 두 WAS를 스위치 껐다다 키듯 왔다갔다 하며 사용한다 가정**
- WAS에서 다른 WAS로 실행을 이동해도 똑같은 Redis를 공유하기 때문에 세션과 달리 유지가 지속된다.

### ✅요청 & 응답

|  | Request_Header  | Request_Body | Request_Cookie | Response_Header | Response_Cookie |
| --- | --- | --- | --- | --- | --- |
| 로그인 |  | ID & PW |  | Access Token | Refresh Token |
| 토큰 재발급 |  |  | Refresh Token | Access Token | Refresh Token |
| 로그아웃 | Access Token |  | Refresh Token |  |  |

### ✅기능 구현

1. **회원가입**
    - 비밀번호 형식에 맞지 않으면 Exception Return
    
2. **일반** **로그인**
    - 로그인 성공시 발급된 Refresh Token Redis에 저장
    - 로그인 실패시 Exception Return

1. **OAuth2 로그인**
    - 구글 , 네이버, 카카오 소셜 로그인 구현
    - code으로 전달 받아서 access token 요청 후 사용자 데이터 받는다.
    - 제공 받은 사용자 데이터로 강제 회원가입 진행
        - 이미 존재하는 회원이면 회원가입 진행하지 않고, 바로 Token 반환
    - 회원가입 진행 완료 후 Access Token은 Body로 Refresh Token은 Cookie로 반환

1. **API 요청 (리소스 요청)**
    - Authorization Header에서 Access Token을 담아서 요청
    - 로그 아웃된 Access Token인지 확인하기 위해서 Redis에서 확인
        - 로그아웃된 Access Token은 Redis에 “BLACK_LIST_” prefix가 붙은상태로 저장됨.
    - Redis에 존재하지 않는 Access Token이면 Token 유효성 검사 진행
    - 올바른 토큰이면 API 응답, 그렇지 않으면 Exception Return
    
2. **Token 재발급**
    - Cookie에서 Refresh Token을 담아서 요청
    - BackEnd Server에서 Client IP 획득
    - Refresh Token 유효성 검사 진행 → 올바르지 않으면 Exception Return
    - Refresh Token이 Redis에 존재하는지 확인 → 존재하지 않으면 Exception Return
    - 재발급을 요청한 IP와 Redis에 Refresh Token Key의 Value로 가지고 있던 IP랑 비교
        - IP가 같다면, 올바른 Client가 요청했다고 판단하여 
        → 기존 Refresh Token 삭제 → 새로운 Refresh Token 발급 후 → Redis에 새로 저장
        - IP가 다르다면, 올바른 Client가 요청하지 않았다고 판단하여 → Refresh Token 삭제
    - Access Token은 Response Body로 반환 & Refresh Token은 Cookie로 저장
    
3. **로그아웃**
    - Authorization Header에 Access Token을 담아서 요청 
    & Cookie에 Refresh Token  담아서 요청
    - Access Token 유효성 검사 진행 → 올바르지 않으면 Exception 반환
    - Client로 부터 전달받은 Refresh Token을 Key로 가지는 Redis 데이터 삭제
    - Client로 부터 전달받은 Access Token의 유효 기간만틈 Redis에 prefix를 붙여서 저장
        - 남은 Access Token의 유효기간만큼 Redis에 Black_List로써 저장하고, 시간이 지나면 알아서 삭제
    - Cookie에서 Refresh Token을 담는 공간 null처리
    
4. **중복 로그인 방지**
    - 여러 브라우저를 통해서 하나의 계정으로 2번 로그인 하는 경우
    - 맨처음 로그인을 통해 Redis에 저장했던 Refresh Token은 2번째 로그인을 통해서
        
        더 이상 사용하지 못하도록 Redis에서 “Duplicate Login Token”으로 관리
        
    - 첫번째 발급받은 Refresh Token은 Redis에서 “Duplicate”으로 관리되고 있기 때문에
    더 이상 Token 재발급을 진행하지 못 하여, 강제 로그아웃 된다.
    
     
    

### ✅Test

- ✅로그인
    
    ![5](https://user-images.githubusercontent.com/91618389/186608843-9fa81e1d-a13d-4a19-917b-e61df4112b7e.png)
    
    로그인 성공시 Response Body에 Access Token 반환
    
    ![6](https://user-images.githubusercontent.com/91618389/186609199-b21372e8-37ab-4f46-bec4-8a6a96c69f3a.png)
    
    → 로그인 성공시 Redis의 Key 값으로 Refresh Token 할당
    
    → 추가적으로, 해당 User의 Id값이 Key값으로 들어간다. value는 최신 Refresh Token을 할당하고 있다.
    

- ✅인증이 필요한 요청
    
    ![7](https://user-images.githubusercontent.com/91618389/186609208-05650c38-1652-4562-9e7c-86f5e8e6007f.png)
    
    Header Authorization에 Access Token 담아서 요청
    

- ✅토큰 재발급
    
    ![8](https://user-images.githubusercontent.com/91618389/186609227-6cfa127a-30fe-452c-9762-13acc0a6b596.png)
    
    Refresh Token만 Cookie에 담는다.
    재발급시 기존의 Refresh Token은 Redis에서 사라지고, 새로운 Refresh Token이 저장된다.
    

- ✅로그아웃
    
    ![9](https://user-images.githubusercontent.com/91618389/186609244-2c331ba7-9c16-4917-a779-24f63d42487f.png)
    
    로그아웃 요청시 Header에 Access Token & Cookie에 Refresh Token 담아서 요청
    해당 로그아웃 하고자 하는 계정이 가지고 있던 Refresh Token은 Redis에서 삭제됨
    
    로그아웃 요청이 들어온 Access Token에 대해서는 Redis에 Black_List로써 저장
    
    토큰의 Prefix에 특정 String을 추가해서 Redis에 저장
    
    ![logout](https://user-images.githubusercontent.com/91618389/186656614-7098fa7c-5c90-4657-b27f-8322d7ebc790.png)
    
- ✅중복 로그인 방지
    
    
    ![11](https://user-images.githubusercontent.com/91618389/186609282-b63f3cbf-99e9-49a4-a5e8-04f1f83b6a86.png)
    
    재로그인시 새로운 Refresh Token이 발급되고, 
    
    앞전의 Refresh Token은 “Dulicate Login”으로 관리
    
    Duplicate Login으로 처리된 Refresh Token으로 Cookie를 통해서 재발급 요청시,
    
    ![12](https://user-images.githubusercontent.com/91618389/186609293-fc8c1be8-c059-4c63-ad62-902a80842a21.png)
    
    → 중복 로그인 때문에, 토큰을 재발급 받을 수 없어서 강제적으로 로그아웃이 가능하게 해야한다.

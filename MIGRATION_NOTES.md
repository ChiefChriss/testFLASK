# Database Migration Notes

## Recent Schema Changes

### 1. Task Comments Feature (Jira-Style)

A new `TaskComment` model has been added to support Jira-style commenting on tasks.

### 2. Employee ID & User Account Creation

- **Employee Model Updated**: Added `employee_id` field (unique, auto-generated)
- **User Account Required**: All new employees must have a username and password
- **Auto-Generated IDs**: Format `EMP-XXXXX` (e.g., EMP-12345)

### 3. In-App Notifications System

A new `Notification` model has been added for real-time user notifications.

- **Notification Types**: task_assigned, status_changed, comment_added, group_task
- **Bell Icon**: Shows unread count in navbar
- **Dropdown**: Recent 5 notifications with quick actions
- **Full Page**: View all notifications at `/notifications`

### To apply the changes:

1. **Backup your database** (if you have important data):
   ```bash
   copy valmed.db valmed.db.backup
   ```

2. **Reinitialize the database**:
   ```bash
   flask init-db
   ```

   **Note:** This will drop all existing data and recreate tables with the new schema.

### New Features Added:

#### Task Comments:
- **TaskComment Model**: Stores comments on tasks
- **Permission System**: Only task creator, assignee, group members, or admins can comment
- **Comment CRUD**: Users can add, edit (own comments), and delete (own comments) 
- **Task Detail Page**: View full task details with all comments
- **Comment Counter**: Shows number of comments on each task card

#### Employee Management:
- **Random Employee ID**: Auto-generated unique ID for each employee
- **Username/Password Required**: All employees get a user account upon creation
- **Username Column**: Now displayed in employee table
- **Enhanced Security**: Each employee has login credentials from day one

### New Routes:

- `GET /tasks/<id>/view` - View task details with comments
- `POST /tasks/<id>/comment` - Add a comment
- `POST /tasks/<id>/comment/<comment_id>/edit` - Edit a comment
- `POST /tasks/<id>/comment/<comment_id>/delete` - Delete a comment
- `POST /tasks/<id>/delete` - Delete a task (admin only)

